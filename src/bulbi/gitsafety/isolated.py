"""Isolated mode (spec §3): the box owns a small git dir; history is shared read-only.

* :class:`HostRefsExporter` reads what the box repo needs from the host repository:
  its refs (``for-each-ref``), ``HEAD``s and object format. Never its config.
* :class:`BoxRepo` builds, refreshes and checks the box repo through the box handle.
  Files are written by Bulbi (``put_archive``), the config has no exec-capable keys and
  ``gc.auto = 0``, and ``objects/info/alternates`` points at the host's ``objects/``,
  mounted read-only.
* :class:`BundlePuller` brings the box's commits back as a ``git bundle`` streamed out of
  the box, fetched into ``refs/remotes/bulbi/*``. Host git never opens the box repo.
"""

from __future__ import annotations

import re
import shlex
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from io import BytesIO
from pathlib import Path

from bulbi.agents.ports import ContainerHandle, ExecResult
from bulbi.constants import CONTAINER_HOME
from bulbi.container.execstream import BoxStream
from bulbi.errors import GitSafetyError, SandboxError
from bulbi.gitsafety.hostgit import HostGit
from bulbi.gitsafety.layout import GIT_DIR_NAME, WORKTREE_ADMIN_DIR
from bulbi.project.locator import Project

HOST_OBJECTS_MOUNT = "/bulbi/host-objects"
STAGE_DIR = f"{CONTAINER_HOME}/.bulbi-git-stage"
PULL_NAMESPACE = "refs/remotes/bulbi"
BRANCH_PREFIX = "refs/heads/"
EXPORTED_REFS = ("refs/heads", "refs/tags")
POINTERS_DIR = "git-pointers"
BROKEN_PREFIX = ".bulbi-broken-"
# The box runs git itself, so the image must have it.
REQUIRED_TOOL = "git"
PACKED_REFS_HEADER = "# pack-refs with: peeled fully-peeled sorted \n"
_REF_LINE = re.compile(r"^([0-9a-f]{40,64}) (refs/\S+)$")
BROKEN_HISTORY = (
    "host history changed under the box (objects it relies on were pruned); run "
    "`bulbi pull` to save the agent's commits, then `bulbi restart` to rebuild"
)


def safe_config(object_format: str) -> str:
    """The box repo's config: nothing that runs a program, and no automatic gc (which
    could only ever drop the box's own objects, but must not repack or prune)."""
    version = 0 if object_format == "sha1" else 1
    lines = [
        "[core]",
        f"\trepositoryformatversion = {version}",
        "\tfilemode = true",
        "\tbare = false",
        "\tlogallrefupdates = true",
        "[gc]",
        "\tauto = 0",
    ]
    if version:
        lines += ["[extensions]", f"\tobjectformat = {object_format}"]
    return "\n".join(lines) + "\n"


@dataclass(frozen=True)
class HostRef:
    name: str
    target: str
    peeled: str | None = None


@dataclass(frozen=True)
class CheckoutSlot:
    """A linked worktree: its admin-dir name, path (the same in the box) and ``HEAD``."""

    name: str
    checkout: Path
    head: str


@dataclass(frozen=True)
class HostRepoState:
    """What the box repo is built from."""

    object_format: str
    head: str
    refs: tuple[HostRef, ...]
    slots: tuple[CheckoutSlot, ...] = ()

    @property
    def tips(self) -> tuple[str, ...]:
        return tuple(ref.target for ref in self.refs if ref.name.startswith(BRANCH_PREFIX))

    def packed_refs(self) -> str:
        lines = [PACKED_REFS_HEADER]
        for ref in sorted(self.refs, key=lambda ref: ref.name):
            lines.append(f"{ref.target} {ref.name}\n")
            if ref.peeled:
                lines.append(f"^{ref.peeled}\n")
        return "".join(lines)


class HostRefsExporter:
    """Reads refs, ``HEAD``s and the object format of the host repository.

    git runs with ``--git-dir`` on the common dir (no worktree discovery); ``HEAD`` files
    are read directly. In isolated mode the box never sees any of these files.
    """

    def __init__(self, git: HostGit | None = None) -> None:
        self._git = git or HostGit()

    def export(self, project: Project) -> HostRepoState:
        git_dir = _git_dir(project)
        listed = self._run(
            git_dir,
            "for-each-ref",
            "--format=%(objectname) %(refname) %(*objectname)",
            *EXPORTED_REFS,
        )
        refs = []
        for line in listed.splitlines():
            target, name, *peeled = line.split(" ")
            refs.append(HostRef(name, target, peeled[0] if peeled and peeled[0] else None))
        object_format = self._run(git_dir, "rev-parse", "--show-object-format").strip()
        slots = []
        for worktree in project.linked_worktrees:
            admin = project.admin_dir(worktree)
            if admin is not None:
                slots.append(CheckoutSlot(admin.name, worktree, _head(admin)))
        return HostRepoState(object_format or "sha1", _head(git_dir), tuple(refs), tuple(slots))

    def has_object(self, project: Project, object_id: str) -> bool:
        result = self._git.run(["--git-dir", str(_git_dir(project)), "cat-file", "-e", object_id])
        return result.returncode == 0

    def _run(self, git_dir: Path, *args: str) -> str:
        result = self._git.run(["--git-dir", str(git_dir), *args])
        if result.returncode != 0:
            raise SandboxError(f"git {args[0]} failed on {git_dir}: {result.stderr.strip()}")
        return result.stdout


def _git_dir(project: Project) -> Path:
    if project.git_dir is None:
        raise SandboxError('[git] mode = "isolated" needs a git repository')
    return project.git_dir


def _head(git_dir: Path) -> str:
    try:
        return (git_dir / "HEAD").read_text().strip()
    except OSError as exc:
        raise SandboxError(f"cannot read {git_dir / 'HEAD'}: {exc}") from exc


def pointer_files(project: Project, pointers_dir: Path) -> dict[Path, Path]:
    """Each linked worktree's ``.git`` -> the host file holding Bulbi's pointer for it."""
    pointers = {}
    for worktree in project.linked_worktrees:
        admin = project.admin_dir(worktree)
        if admin is not None:
            pointers[worktree / GIT_DIR_NAME] = pointers_dir / admin.name
    return pointers


def pointer_text(project: Project, admin_name: str) -> str:
    return f"gitdir: {_git_dir(project) / WORKTREE_ADMIN_DIR / admin_name}\n"


@dataclass
class BoxRepo:
    """The box-owned git dir, mounted at the main checkout's ``.git`` inside the box."""

    handle: ContainerHandle
    project: Project
    clock: datetime = field(default_factory=lambda: datetime.now(UTC))

    @property
    def git_dir(self) -> str:
        return str(_git_dir(self.project))

    def exists(self) -> bool:
        return self.handle.exec(["test", "-f", f"{self.git_dir}/HEAD"]).succeeded

    def build(self, state: HostRepoState) -> None:
        """Create the box repo from the host's refs (the volume must hold no repo)."""
        if not self.handle.exec(["test", "-w", self.git_dir]).succeeded:
            # A fresh volume's mount point belongs to root; root (without capabilities)
            # may still open up its own directory to the box user.
            self._require(self.handle.exec(["chmod", "0777", self.git_dir], as_root=True))
        self._stage("config", safe_config(state.object_format))
        self._stage("alternates", f"{HOST_OBJECTS_MOUNT}\n")
        self._stage("packed-refs", state.packed_refs())
        self._stage("HEAD", f"{state.head}\n")
        git_dir = shlex.quote(self.git_dir)
        stage = shlex.quote(STAGE_DIR)
        script = [
            "set -eu",
            f"git init -q --bare --object-format={shlex.quote(state.object_format)} {git_dir}",
            f"mv {stage}/config {git_dir}/config",
            f"mv {stage}/alternates {git_dir}/objects/info/alternates",
            f"mv {stage}/packed-refs {git_dir}/packed-refs",
            f"mv {stage}/HEAD {git_dir}/HEAD",
            *self._index_lines(self.project.root),
        ]
        self._script(script)
        for slot in state.slots:
            self.add_checkout(slot)

    def refresh(self, state: HostRepoState) -> None:
        """An existing box repo: add host branches and checkouts it lacks; never overwrite."""
        git_dir = shlex.quote(self.git_dir)
        lines = [
            f"git --git-dir={git_dir} update-ref {shlex.quote(ref.name)} {ref.target} '' "
            "2>/dev/null || true"
            for ref in state.refs
        ]
        if lines:
            self._script(lines)
        for slot in state.slots:
            if not self.has_checkout(slot.name):
                self.add_checkout(slot)

    def has_checkout(self, name: str) -> bool:
        head = f"{self.git_dir}/{WORKTREE_ADMIN_DIR}/{name}/HEAD"
        return self.handle.exec(["test", "-f", head]).succeeded

    def add_checkout(self, slot: CheckoutSlot) -> None:
        """An admin dir for a linked worktree, at the host's name, and its index."""
        self._stage(f"HEAD-{slot.name}", f"{slot.head}\n")
        admin = shlex.quote(f"{self.git_dir}/{WORKTREE_ADMIN_DIR}/{slot.name}")
        gitdir = shlex.quote(f"{slot.checkout}/{GIT_DIR_NAME}")
        script = [
            "set -eu",
            f"mkdir -p {admin}",
            f"printf '%s\\n' {gitdir} > {admin}/gitdir",
            f"printf '../..\\n' > {admin}/commondir",
            f"mv {shlex.quote(f'{STAGE_DIR}/HEAD-{slot.name}')} {admin}/HEAD",
            *self._index_lines(slot.checkout),
        ]
        self._script(script)

    def healthy(self) -> bool:
        """Every branch tip and its parents resolve (spec §3.3); cheap ``cat-file -e``."""
        git = f"git --git-dir={shlex.quote(self.git_dir)}"
        script = [
            f"for tip in $({git} for-each-ref --format='%(objectname)' refs/heads); do",
            f'  {git} cat-file -e "$tip" || exit 3',
            f'  for parent in $({git} rev-parse "$tip^@") ; do',
            f'    {git} cat-file -e "$parent" || exit 3',
            "  done",
            "done",
        ]
        return self.handle.exec(["bash", "-c", "\n".join(script)]).succeeded

    def set_aside(self) -> str:
        """Move a broken repo into ``.bulbi-broken-<time>/`` inside the volume (kept)."""
        aside = f"{self.git_dir}/{BROKEN_PREFIX}{self.clock.strftime('%Y%m%dT%H%M%SZ')}"
        git_dir, quoted = shlex.quote(self.git_dir), shlex.quote(aside)
        self._script(
            [
                "set -eu",
                f"mkdir {quoted}",
                f"find {git_dir} -mindepth 1 -maxdepth 1 ! -name '{BROKEN_PREFIX}*' "
                f"-exec mv {{}} {quoted} ';'",
            ]
        )
        return aside

    # ---- helpers -----------------------------------------------------------------------

    def _stage(self, name: str, content: str) -> None:
        self.handle.write_file(f"{STAGE_DIR}/{name}", content)

    @staticmethod
    def _index_lines(checkout: Path) -> list[str]:
        """Rebuild a checkout's index from its HEAD (an unborn HEAD has none)."""
        quoted = shlex.quote(str(checkout))
        return [
            f"if git -C {quoted} rev-parse -q --verify HEAD >/dev/null; then",
            f"  git -C {quoted} read-tree HEAD",
            f"  git -C {quoted} update-index -q --refresh >/dev/null || true",
            "fi",
        ]

    def _script(self, lines: Sequence[str]) -> None:
        self._require(self.handle.exec(["bash", "-c", "\n".join(lines)]))

    @staticmethod
    def _require(result: ExecResult) -> None:
        if not result.succeeded:
            raise SandboxError(
                f"failed to prepare the box's git repository: {result.output.strip()}"
            )


@dataclass(frozen=True)
class PullResult:
    refs: tuple[str, ...]


class BundlePuller:
    """``bulbi pull`` (spec §3.2): bundle in the box, verify and fetch on the host."""

    def __init__(
        self,
        stream: BoxStream,
        project: Project,
        git: HostGit | None = None,
        box_git_dir: str | None = None,
    ) -> None:
        self._stream = stream
        self._project = project
        self._git = git or HostGit()
        self._exporter = HostRefsExporter(self._git)
        self._box_git_dir = box_git_dir or str(_git_dir(project))

    def pull(self, branch: str | None = None) -> PullResult:
        box_refs = self._box_branches()
        if branch is not None:
            wanted = BRANCH_PREFIX + branch
            box_refs = {name: tip for name, tip in box_refs.items() if name == wanted}
            if not box_refs:
                raise GitSafetyError(f"the box has no branch '{branch}'")
        if not box_refs:
            return PullResult(())
        missing = [tip for tip in box_refs.values() if not self._host_has(tip)]
        if missing:
            self._fetch_bundle(box_refs)
        else:  # Nothing new to transfer: the host already has every tip.
            for name, tip in box_refs.items():
                self._host_git("update-ref", self._remote_name(name), tip)
        return PullResult(tuple(self._remote_name(name) for name in sorted(box_refs)))

    def _box_branches(self) -> dict[str, str]:
        listing = BytesIO()
        result = self._stream.run(
            [
                "git",
                f"--git-dir={self._box_git_dir}",
                "for-each-ref",
                "--format=%(objectname) %(refname)",
                BRANCH_PREFIX.rstrip("/"),
            ],
            listing,
        )
        if not result.succeeded:
            raise GitSafetyError(f"cannot list the box's branches: {result.output.strip()}")
        branches = {}
        for line in listing.getvalue().decode(errors="replace").splitlines():
            match = _REF_LINE.match(line)
            if match and self._valid_ref(match.group(2)):
                branches[match.group(2)] = match.group(1)
        return branches

    def _fetch_bundle(self, box_refs: Mapping[str, str]) -> None:
        exclude = [tip for tip in self._host_tips() if tip not in box_refs.values()]
        with tempfile.TemporaryDirectory(prefix="bulbi-pull-") as temporary:
            bundle = Path(temporary) / "box.bundle"
            argv = ["git", f"--git-dir={self._box_git_dir}", "bundle", "create", "-"]
            argv += [*sorted(box_refs), *(["--not", *exclude] if exclude else [])]
            with bundle.open("wb") as sink:
                result = self._stream.run(argv, sink)
            if not result.succeeded:
                raise GitSafetyError(f"git bundle failed in the box: {result.output.strip()}")
            self._host_git("bundle", "verify", "-q", str(bundle))
            refspecs = [f"+{name}:{self._remote_name(name)}" for name in sorted(box_refs)]
            self._host_git("fetch", "--no-tags", "--no-write-fetch-head", str(bundle), *refspecs)

    def _host_tips(self) -> tuple[str, ...]:
        return self._exporter.export(self._project).tips

    def _host_has(self, object_id: str) -> bool:
        return self._exporter.has_object(self._project, object_id)

    def _valid_ref(self, name: str) -> bool:
        return self._git.run(["check-ref-format", name]).returncode == 0

    @staticmethod
    def _remote_name(name: str) -> str:
        return f"{PULL_NAMESPACE}/{name.removeprefix(BRANCH_PREFIX)}"

    def _host_git(self, *args: str) -> None:
        result = self._git.run(["--git-dir", str(_git_dir(self._project)), *args])
        if result.returncode != 0:
            raise GitSafetyError(f"git {args[0]} failed: {result.stderr.strip()}")
