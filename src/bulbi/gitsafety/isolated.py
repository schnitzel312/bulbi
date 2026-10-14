"""Isolated mode (spec §3): the box works on its own clone, kept in a Docker volume.

* :class:`BoxClones` seeds the clone from the host repository (through a read-only
  mount, ``git clone --no-local``) and exports it back for ``bulbi pull``.
* :class:`BoxClonePuller` vets an exported clone and fetches its branches into
  ``refs/remotes/bulbi/*`` with the host's git.
"""

from __future__ import annotations

import tempfile
from dataclasses import dataclass
from pathlib import Path

from bulbi.constants import DOCKER_LABEL_PROJECT
from bulbi.container.gitvolume import GitVolumeManager
from bulbi.container.mounts import BindMount, PlannedMount, VolumeMount
from bulbi.errors import GitSafetyError, SandboxError
from bulbi.gitsafety.baseline import GitBaseline
from bulbi.gitsafety.checks import ExecConfigCheck, ScanContext
from bulbi.gitsafety.config import HostGitConfigReader
from bulbi.gitsafety.exec_keys import ExecConfigRegistry
from bulbi.gitsafety.findings import GitFinding, NewGitDirFinding
from bulbi.gitsafety.hostgit import HostGit
from bulbi.gitsafety.inventory import GitInventory
from bulbi.gitsafety.layout import COMMONDIR_FILE, GIT_DIR_NAME
from bulbi.project.locator import Project

HOST_GIT_MOUNT = "/bulbi/host"
CLONE_MOUNT = "/bulbi/clone"
EXPORT_MOUNT = "/bulbi/out"
PULL_NAMESPACE = "refs/remotes/bulbi"
# The seeding helper runs the box image's git, so the image must have it.
REQUIRED_TOOL = "git"

# Clone (or refresh) the host repository into the volume, then give every checkout
# its own admin dir at the host's name. Existing branches in the clone are never
# overwritten: host branches arrive as refs/remotes/host/* and only missing local
# branches are created from them. Arguments: pairs of (admin name, checkout path).
SEED_SCRIPT = r"""
set -eu
export HOME=/tmp GIT_CONFIG_NOSYSTEM=1
export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=safe.directory GIT_CONFIG_VALUE_0='*'
host=/bulbi/host clone=/bulbi/clone
if [ ! -f "$clone/HEAD" ]; then
    git clone --bare --no-local --quiet "$host" "$clone"
    git --git-dir="$clone" remote remove origin
    git --git-dir="$clone" config core.bare false
    git --git-dir="$clone" read-tree HEAD 2>/dev/null || true
else
    git --git-dir="$clone" fetch --quiet --no-tags "$host" '+refs/heads/*:refs/remotes/host/*'
    git --git-dir="$clone" for-each-ref --format='%(refname:strip=3)' refs/remotes/host/ |
    while read -r branch; do
        git --git-dir="$clone" show-ref --quiet --verify "refs/heads/$branch" ||
            git --git-dir="$clone" branch --quiet "$branch" "refs/remotes/host/$branch"
    done
fi
while [ "$#" -ge 2 ]; do
    name=$1 checkout=$2
    shift 2
    admin="$clone/worktrees/$name"
    [ -d "$admin" ] && continue
    mkdir -p "$admin"
    printf '%s/.git\n' "$checkout" > "$admin/gitdir"
    printf '../..\n' > "$admin/commondir"
    cp "$host/worktrees/$name/HEAD" "$admin/HEAD"
    GIT_DIR="$admin" git read-tree HEAD 2>/dev/null || true
done
chown -R bulbi:bulbi "$clone"
"""

# Copy the clone out for `bulbi pull`. Argument: the host user's uid:gid.
EXPORT_SCRIPT = r"""
set -eu
cp -a /bulbi/clone/. /bulbi/out/
chown -R "$1" /bulbi/out 2>/dev/null || true
"""


@dataclass(frozen=True)
class CheckoutSlot:
    """A linked worktree's admin-dir name and its path (the same inside the box)."""

    name: str
    checkout: Path


def checkout_slots(project: Project) -> list[CheckoutSlot]:
    slots = []
    for worktree in project.linked_worktrees:
        admin = project.admin_dir(worktree)
        if admin is not None:
            slots.append(CheckoutSlot(admin.name, worktree))
    return slots


class BoxClones:
    """Seeds and exports the clone volumes of isolated boxes."""

    def __init__(self, volumes: GitVolumeManager, owner: tuple[int, int] | None = None) -> None:
        self._volumes = volumes
        self._owner = owner

    def exists(self, volume: str) -> bool:
        return self._volumes.exists(volume)

    def seed(self, image: str, volume: str, project: Project) -> None:
        """Create or refresh ``volume`` from the host repository (read-only to the helper)."""
        if project.git_dir is None:
            raise SandboxError('[git] mode = "isolated" needs a git repository')
        self._volumes.ensure(volume, {DOCKER_LABEL_PROJECT: str(project.key)})
        args = [
            part for slot in checkout_slots(project) for part in (slot.name, str(slot.checkout))
        ]
        mounts: list[PlannedMount] = [
            BindMount(str(project.git_dir), HOST_GIT_MOUNT, read_only=True),
            VolumeMount(volume, CLONE_MOUNT),
        ]
        result = self._volumes.run_helper(image, SEED_SCRIPT, args, mounts)
        if not result.succeeded:
            raise SandboxError(f"failed to prepare the box's git clone: {result.output.strip()}")

    def export(self, image: str, volume: str, destination: Path) -> None:
        """Copy the clone in ``volume`` to the (empty) host directory ``destination``."""
        if not self._volumes.exists(volume):
            raise GitSafetyError(f"no box clone ({volume}) yet; run `bulbi run` first")
        owner = ":".join(map(str, self._owner)) if self._owner else "0:0"
        mounts: list[PlannedMount] = [
            VolumeMount(volume, CLONE_MOUNT, read_only=True),
            BindMount(str(destination), EXPORT_MOUNT, read_only=False),
        ]
        result = self._volumes.run_helper(image, EXPORT_SCRIPT, [owner], mounts)
        if not result.succeeded:
            raise GitSafetyError(f"failed to copy the box's clone: {result.output.strip()}")


@dataclass(frozen=True)
class PullResult:
    refs: tuple[str, ...]


class BoxClonePuller:
    """``bulbi pull``: fetch the box's branches into ``refs/remotes/bulbi/*`` (spec §3).

    Local-transport ``upload-pack`` runs on the host and reads the source repository's
    config, so the exported clone is vetted first: any exec-capable key in its config
    (or anything it includes), or a ``.git``/``commondir`` redirecting git elsewhere,
    refuses the pull.
    """

    def __init__(
        self,
        clones: BoxClones,
        git: HostGit | None = None,
        registry: ExecConfigRegistry | None = None,
        home: Path | None = None,
    ) -> None:
        self._clones = clones
        self._git = git or HostGit()
        self._registry = registry or ExecConfigRegistry.builtin()
        self._home = home

    def pull(
        self, image: str, volume: str, project_root: Path, branch: str | None = None
    ) -> PullResult:
        with tempfile.TemporaryDirectory(prefix="bulbi-pull-") as temporary:
            export = Path(temporary).resolve() / "clone"
            export.mkdir()
            self._clones.export(image, volume, export)
            return self.fetch(export, project_root, branch)

    def fetch(self, export: Path, project_root: Path, branch: str | None = None) -> PullResult:
        """Vet an exported clone, then fetch from it with the host's git."""
        findings = self.vet(export)
        if findings:
            listed = "\n".join(f"  {f.path}: {f.describe()}" for f in findings)
            raise GitSafetyError(
                "refusing to pull: the box's clone would make git run code on this machine:\n"
                f"{listed}\nRemove these settings inside the box (`bulbi shell`), then pull again."
            )
        if (
            branch is not None
            and self._git.run(["check-ref-format", "--branch", branch]).returncode
        ):
            raise GitSafetyError(f"'{branch}' is not a valid branch name")
        source = branch or "*"
        refspec = f"+refs/heads/{source}:{PULL_NAMESPACE}/{source}"
        fetched = self._git.run(
            ["-c", "protocol.file.allow=always", "fetch", "--no-tags", str(export), refspec],
            cwd=project_root,
        )
        if fetched.returncode != 0:
            raise GitSafetyError(
                f"git fetch from the box's clone failed: {fetched.stderr.strip()}"
            )
        listed_refs = self._git.run(
            ["for-each-ref", "--format=%(refname:short)", PULL_NAMESPACE], cwd=project_root
        )
        return PullResult(tuple(line for line in listed_refs.stdout.splitlines() if line))

    def vet(self, export: Path) -> list[GitFinding]:
        findings: list[GitFinding] = [
            NewGitDirFinding(path)
            for path in (export / GIT_DIR_NAME, export / COMMONDIR_FILE)
            if path.exists() or path.is_symlink()
        ]
        inventory = GitInventory(HostGitConfigReader(self._git), home=self._home)
        snapshot = inventory.take((), export)
        # Every file in the include chain counts, wherever it lives.
        anywhere = GitBaseline(roots=(Path(export.anchor),), common_dir=export)
        context = ScanContext(anywhere, snapshot, self._registry)
        findings.extend(ExecConfigCheck().findings(context))
        return findings
