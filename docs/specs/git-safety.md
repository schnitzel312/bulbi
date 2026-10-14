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
