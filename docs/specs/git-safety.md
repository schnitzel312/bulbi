# Spec: Git safety: stop agents from planting code that runs on the host via git

Status: approved by the user (option 1 now, option 3 as opt-in)
Builds on `docs/specs/sandbox-isolation.md` (§3.6, §9). Read that first.

## 1. Threat
When the **user** runs `git` on the host, git reads repository metadata the agent could write (the agent has read-write access to the project and worktrees). Several settings make git execute commands: `core.fsmonitor`, `core.hooksPath`, `core.sshCommand`, `core.pager`, `core.editor`, `core.askPass`, `credential.helper`, `diff.external`, `diff.*.textconv`, `filter.*.clean|smudge|process`, `merge.*.driver`, `gpg.program`, `gpg.*.program`, `sequence.editor`, `uploadpack.packObjectsHook`, and `alias.*` values starting with `!`, among others. Hooks in any hooks dir git consults do the same.

Already closed by the read-only overlays (sandbox spec §3.6 plus the review fixes):
- `.git/hooks`, `.git/config`;
- each worktree admin dir's `config`, `config.worktree`, `commondir` and `gitdir`;
- the linked worktree's top-level `.git` file.

The review found two attacks the overlays don't cover:
- **Vector C:** a new nested `.git` (dir or `gitdir:` file) created after box start, such as `src/.git` pointing at an agent-controlled gitdir.
- New worktree admin dirs created after start, under `.git/worktrees/<new>/`, with an agent-chosen `commondir`/`config`, and any files the agent controls that such a pointer can redirect git to.

The reviewer showed each of these produces host code execution when the user then runs `git status` (repro: `core.fsmonitor` creating a marker file).

## 2. Mode A: `guarded` (default, ships now)
The agent keeps full git use inside the box (commit, branch, `git worktree add`). Bulbi **detects and neutralises** dangerous git metadata on the host side.

### 2.1 Baseline
At box creation, record a manifest of every git metadata entry under the mounted project roots in `.bulbi/git-baseline.json`:
- the paths of all `.git` dirs and files;
- every worktree admin dir with its `commondir`/`gitdir` targets;
- a hash of every config file and hooks dir.

### 2.2 Scan (`GitSafetyScanner`)
Runs:
- on the host, after every session ends;
- before every `bulbi run`/`shell` attach;
- explicitly as `bulbi git-scan`.

It walks the mounted roots, skipping large ignored dirs such as `node_modules`, `.venv` and `target`, with a configurable time budget. It reports a **finding** for each of:
1. A `.git` dir or file not in the baseline (vector C), or a new `.git/worktrees/<x>/` admin dir.
2. Any `.git` file, `commondir` or `gitdir` pointing **outside** the project's own git common dir and mounted roots, or into a path the box can write that isn't a legitimate git dir.
3. Any config file git would read for these repos (repo config, `config.worktree`, `include.path` / `includeIf` targets, recursively) that sets an **exec-capable key** (the §1 list, kept in one registry class so it can be extended) whose value differs from the baseline.
4. Any hooks dir (default or via `core.hooksPath`) containing executable files that differ from the baseline.

### 2.3 Neutralise
Whatever the finding, the files are moved aside, never deleted, so the user can restore them. Bulbi:
- moves a new nested `.git` to `.bulbi/quarantine/<timestamp>/<relpath>`;
- comments out a dangerous key, with a backup in quarantine;
- moves an offending hook to quarantine.

`bulbi git-restore <id>` puts quarantined items back. The policy is configurable: `[git] on_finding = "quarantine"` (default) or `"block"`. With `"block"`, Bulbi refuses to attach and prints the findings but changes nothing.

### 2.4 Report
A red, explicit message names every file and key, what was done and how to restore it. Findings are also appended to the audit log with `method = "GIT"` and `reason = git_exec_config | new_git_dir | foreign_pointer | hook_changed`.

### 2.5 Documented residual
Between the agent writing a file and the next scan (session end or the next attach), the user could still run host `git` in the affected directory. `bulbi check` and the docs say:
- while sessions are live, run git for this project inside the box (`bulbi shell`) or run `bulbi git-scan` first;
- for a full guarantee, use mode B.

## 3. Mode B: `isolated` (opt-in, `[git] mode = "isolated"`)
The agent never has write access to any host git metadata.
- **The box gets its own clone:**
  - the repo is cloned into a named volume `bulbi-git-<project>` at box creation (`git clone --no-local`, or a fetch from the host repo through a read-only mount);
  - the host's `.git` dirs and files are **not** mounted, so they're absent in the box;
  - working-tree files remain bind-mounted read-write as usual;
  - in the box, `GIT_DIR` / `.git` points at the volume clone.
- **Getting the agent's commits back:** `bulbi pull [--branch <b>]` runs on the host and does `git fetch` from the box clone, using host git with `-c protocol.file.allow=always`. Before fetching, it scans the box clone's config with the §2.2 exec-key check, because local-transport upload-pack reads the source repo's config; on findings it refuses. It fetches into `refs/remotes/bulbi/*`, never touching the user's branches.
- **Worktrees in this mode:** each mounted worktree gets its own linked worktree inside the box clone, at the same host path.
- **Tests:** in a docker test, vectors A, B and C produce nothing on the host. A commit made in the box appears after `bulbi pull` as `bulbi/<branch>`.

## 4. Design constraints
- **Follow the repo's conventions:** CLAUDE.md, SOLID, ABCs at extension points. For example:
  - a `GitFinding` hierarchy;
  - a `GitCheck` ABC with one subclass per check in §2.2;
  - an `ExecConfigRegistry`;
  - a `FindingAction` ABC with `Quarantine`/`Block`;
  - a `GitMode` strategy with `Guarded`/`Isolated`, plugged into the mount planner and the session.
- **Never delete user data; never touch anything outside the project roots and `.bulbi/`.**
- **The scanner is pure and testable:** it operates on a filesystem root, and host git is invoked only through an injected runner.

## 5. Verification
- **Unit:** each check positive and negative; the include/includeIf chase; pointer-outside detection; quarantine and restore round trip; block mode; the registry covers the §1 keys; performance budget respected.
- **Docker (`pytest -m docker`):**
  - **Guarded:** reproduce vectors A, B and C from inside a real box. A and B are refused by the read-only filesystem. For C, after the session ends, the scan quarantines it and a following host `git status` creates no marker.
  - **Isolated:** no host marker for A, B or C; `bulbi pull` brings the commit back.
- All test repos are temporary. Never touch the real repository's `.git`.

## 6. Implementation notes (as built)
Code: `src/bulbi/gitsafety/` (host side), `container/mounts.py` (`GitMetadataMounts`), `container/gitvolume.py`, `cli/commands/{git_scan,git_restore,pull}.py`.

**Configuration** (`bulbi.toml`):
```toml
[git]
mode = "guarded"          # or "isolated"
on_finding = "quarantine" # or "block"
scan_budget = "10s"       # an unfinished scan refuses the attach
skip = ["node_modules", ".venv", "target", ...]   # replaces the default list
```

**Refinements and deviations from §2–§3:**
1. **`.bulbi/` is mounted read-only into every box.** The baseline and quarantine would otherwise be agent-writable (the agent could whitelist its own plant), and so were the audit log and the relay pid file.
2. **What the box can write is derived from the mount plan** (`host_exposure`): the scan walks only read-write mounts, including extra `[[mount]]`s, and ignores paths under read-only overlays, masks or the isolated clone volume. Changes there can only be the user's, so the user's own host edits to `.git/config` or `.git/hooks` are never flagged.
3. **New `.git` files and new worktree admin dirs are flagged only when their pointers are not those of an ordinary linked checkout** (§2.2.1). Without this refinement, every in-box `git worktree add` (explicitly allowed by §2), every worktree the user adds on the host, and every submodule would be quarantined. A new `.git` file must lead into a known repository's `worktrees/` or `modules/`. A new admin dir's `commondir` must lead back to its repository, and its `gitdir` must be stale or a `.git` file pointing straight back. Because new items are never added to the baseline, they are re-validated by every scan, and their configs and hooks are checked like any other (this covers the reviewer's late-worktree case). New `.git` *directories* are always findings.
4. **Bare-repository-shaped directories** (`HEAD` + `objects/` + `refs/`) are treated as new git dirs too: git uses such a directory as a repository when run inside it, so it is vector C without a `.git` name.
5. **Exec-config comparison is per file and per value:** a finding is an exec-capable `(key, value)` absent from that file's baseline. Neutralising comments out every line of the key, re-adds the trusted values, verifies with `git config`, and falls back to `git config --unset-all`. A changed config git cannot parse is moved aside. The baseline JSON keeps only exec-capable entries, not whole configs.
6. **The baseline is per profile** (`git-baseline-<profile>.json`), because a read-only profile's box protects everything. Box creation and recreation scan against the old baseline before recording a new one. `bulbi git-restore` marks restored paths as trusted in the baseline.
7. **An incomplete scan (budget exceeded) refuses the attach** whatever `on_finding` is. A failed move (e.g. a permission error) is reported as left in place and also refuses the attach.
8. **Isolated mode still runs the scanner,** because working-tree files stay bind-mounted read-write, so vector C (a new `src/.git`) is still possible there. The clone is seeded and exported by an offline helper container from the box image (`network_mode=none`, only `CHOWN`/`DAC_OVERRIDE`/`FOWNER`). The box itself keeps `cap_drop=ALL`. Isolated mode therefore needs `git` in `[tools] allow` (validated). An existing volume is refreshed into `refs/remotes/host/*`, and only missing local branches are created, so the box's own commits are never overwritten. `bulbi pull` refuses a clone that contains a `.git` or `commondir` (which would redirect `upload-pack`) as well as exec keys. Clone volumes are not removed by `bulbi rm`/`reset` (they may hold unpulled work); remove them with `docker volume rm bulbi-git-…`.
9. **More exec-capable keys than §1 lists** are in `ExecConfigRegistry` (`pager.*`, `remote.*.uploadpack|receivepack|vcs`, `difftool/mergetool/man/browser.*.cmd|path`, `sendemail.*cmd`, `trailer.*.command`, `submodule.*.update = !…`, `core.gitProxy`, …). `core.fsmonitor` booleans are not exec.

**Residual risks** (beyond §2.5):
- Directories in `skip` are not walked (e.g. `node_modules/x/.git`).
- On the first box creation for a project, whatever is already present becomes the baseline.
- In isolated mode, submodules and detached worktree HEADs that no branch reaches are not available in the box clone.
- Users who want host git to ignore implicit bare repositories altogether can set `safe.bareRepository = explicit` in their global git config.
