---
name: disciplined-worktree-promotion
description: Use when evaluating changes in isolated worktrees or short-lived branches and deciding what to promote back to a clean baseline branch.
---

# Disciplined Worktree Promotion

Use this skill to keep exploratory work disposable, promotion decisions evidence-based, and the accepted baseline branch clean.

Use `using-git-worktrees` for worktree creation and detection. This skill governs what to keep, what to discard, and when a change has earned promotion.

## Operating posture

- Start from the accepted baseline branch, not automatically the repository default branch.
- Keep one work item per worktree or short-lived branch.
- Treat exploratory edits, benchmark spikes, and risky ideas as disposable until they earn promotion.
- Keep the baseline branch clean. Promote only deltas that survive review, tests, and proof runs.
- Prefer a narrow, understandable change over a broad rewrite.

## Core rules

1. **Inspect before adding**
   - Read the existing implementation and prior notes first.
   - Look for simplification, deletion, or a tighter use of current code before inventing new structure.

2. **Reduce or fix code first**
   - Prefer removing code, narrowing code paths, or reusing the current structure over introducing new moving parts.
   - If a problem can be solved by deleting redundant logic, collapsing a branch, tightening a condition, or clarifying ownership, do that first.

3. **New helpers are a last resort**
   - Do not add helpers, abstractions, wrappers, coordinators, or new layers by default.
   - Only introduce a helper when the existing code cannot be kept clear and duplication is both real and worth preserving.
   - If you add a helper, explain why in concrete terms and keep it tightly scoped.

4. **Keep phases small and promotable**
   - Prefer one meaningful concern per branch or phase.
   - If several ideas exist, split them into separate experiments so each one can be kept or discarded independently.
   - Avoid bundling speculative performance work with correctness fixes unless they are inseparable.

5. **Do not carry work with stash or hidden state**
   - Do not use stash as a handoff mechanism between experiments.
   - If a delta is worth keeping, prove it and promote it.
   - If it is not worth keeping, discard the worktree or branch.

6. **Use swarms for challenge, not for noise**
   - Use subagents or swarms to challenge assumptions, inspect code from fresh angles, or run independent health checks.
   - Do not use them to create churn or duplicate local investigation.
   - Summarize conclusions as keep, discard, defer, or needs-human-judgment.

7. **Evidence beats plausibility**
   - Do not keep a change because it sounds faster or cleaner.
   - Run the focused tests for the touched area.
   - Run the repository validation that already exists.
   - When a change affects live service paths, run the smallest real-target proof that can disconfirm the change.
   - If the change only touches a narrow tagged or selectable slice, use that same narrow slice for the cloud or hosted proof first.
   - Widen from targeted cloud proof to broader proof only when the narrow proof is ambiguous, shared infrastructure changed, or the benchmark comparison is not trustworthy.
   - For reliability or performance work, compare against the accepted benchmark and judge results in this order:
     1. correctness and completeness
     2. warnings and failure behavior
     3. memory impact
     4. wall-clock time

8. **Keep or discard decisively**
   - Keep a change only if the net result is clearly worth the complexity.
   - Discard experiments that introduce correctness ambiguity, regress memory materially, or add design weight without durable payoff.
   - Record future ideas instead of forcing them into the current branch.

9. **Promotion workflow**
   - Do exploratory work on isolated branches or sessions.
   - When a delta proves itself, replay or preserve only the kept change on a clean baseline-derived branch.
   - Re-run the relevant proof on the promoted branch, not only on the experimental branch.
   - Do not drag discarded experiments, noisy commits, or convenience hacks into the promoted branch.

10. **PR hygiene**
   - Explain the final kept changes in plain language.
   - Fix CI at the root cause; never bypass shared tooling just to get green.
   - Treat review threads as unfinished until you have replied and resolved them.
   - Keep the branch merge-ready, but do not merge unless explicitly asked.

11. **Archive aggressively**
    - Once an exploratory branch has been promoted or discarded, it is safe to archive its worktree and conversation.
   - Keep only the active promotion context and anything still needed to complete the current review.

## Promotion ledger

For each work item, record:

- baseline branch name and baseline commit
- worktree or branch name
- concise hypothesis
- focused local validation commands
- targeted cloud or hosted proof command and selected tests or tags
- benchmark used for correctness, memory, and time comparison
- keep, discard, or defer decision

If work spans more than one repository, package, or deployable unit, record every relevant baseline SHA or version and the exact artifact or bundle used for proof.

## Recommended workflow

1. Start from a clean worktree on the accepted baseline branch, unless this is explicitly stacked work.
2. Read the current code, prior notes, and existing tests before deciding on structure changes.
3. Write down the smallest viable change that could solve the problem.
4. Challenge that plan:
   - Can existing code be reduced instead?
   - Can a branch be removed?
   - Can a current helper be reused?
   - Is a new abstraction actually necessary?
5. If the work is risky or subtle, use subagents for code review, idea scouting, or benchmark-plan validation.
6. Implement the smallest viable delta.
7. Run focused tests first, then the repo validation that already exists.
8. If the change touches a narrow tagged or selectable slice, run the matching narrow cloud or hosted proof before any broader proof.
9. For shared-runtime, live-service, perf, or reliability changes, compare against the current accepted benchmark for correctness, memory, and time.
10. Make a keep/discard call:
    - **Keep** if correctness is solid and the tradeoff is worth it.
    - **Discard** if the gain is noisy, marginal, or correctness becomes less trustworthy.
    - **Defer** if the idea is real but adds too much complexity for the current branch.
11. If kept, promote the clean delta, rerun proof on the promoted branch, then commit.
12. If the narrow cloud proof or benchmark regresses, stop and report the regression before promoting.
13. Clean up the experimental worktree or branch before starting the next work item.

## Cleanup gate

Do not start the next work item until all of these are true:

- baseline branch is clean
- current worktree or branch has a final keep, discard, or defer decision
- no leftover stash is carrying unresolved work
- temporary worktree or branch cleanup is complete, or there is an explicit reason it must stay open
- promotion ledger is updated

## Decision heuristics

- Prefer reliability over raw speed.
- Prefer clarity over cleverness.
- Prefer local edits over framework-building.
- Prefer a proven small win over a larger uncertain redesign.
- Prefer recording a future idea over shipping half of a design.

## What to avoid

- Broad rewrites when a local fix exists.
- New helpers created only to move code around.
- Bundling unrelated changes to save time.
- Starting a second work item before the first has a keep/discard decision.
- Using stash to shuttle unfinished work between branches.
- Treating flaky or suspicious output as success.
- Treating unexercised live-service paths as proven.
- Keeping a performance change that increases risk without durable benefit.
- Making CI pass by weakening tests or bypassing tooling.

## Output style for this skill

When reporting progress or results:

- Lead with the keep/discard/result.
- Say plainly what changed and why it was worth keeping.
- If something is deferred, label it clearly as future work, not hidden scope.
- When uncertain, say what evidence is missing instead of guessing.
