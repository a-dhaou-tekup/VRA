# Moving into Claude Code — step-by-step

You're on Windows with a real GPU. Two viable paths; pick one.

- **Path A — WSL2 (recommended).** Cleanest Unix environment; Claude Code's primary target.
  Ollama runs on Windows and is still reachable from WSL at `localhost:11434`.
- **Path B — native Windows.** Works, needs Git for Windows (Git Bash). Fine if you'd
  rather not touch WSL.

Node.js 18+ is required for the npm install method; the native installer needs nothing.
You also need a paid Claude plan (Pro/Max/Team/Enterprise) or a Console (API) account.

---

## Step 1 — Install Claude Code

**Native installer (no Node needed) — easiest:**
Follow the official setup page for the one-line installer for your OS:
https://docs.claude.com/en/docs/claude-code/setup

**Or via npm (if you already have Node 18+):**
```
npm install -g @anthropic-ai/claude-code
```
Do NOT use `sudo`. If you hit permission errors, install Node via nvm (home-dir) instead.

**WSL2 path:** install your Ubuntu distro first (`wsl --install` in an admin PowerShell,
reboot), open the Ubuntu terminal, then run the installer there — not from PowerShell.

Verify:
```
claude --version
claude doctor      # checks your install + environment, incl. whether it sees your tools
```

---

## Step 2 — Authenticate
```
claude
```
First run opens a browser OAuth flow — log in with your Claude subscription account.
(API-key auth via `ANTHROPIC_API_KEY` is also possible for headless setups, but OAuth
with your subscription is simpler here.)

---

## Step 3 — Drop in the three planning files
Copy these into your project so Claude Code picks them up:

- `CLAUDE.md` → **repo root** (`PFE 2/vra/CLAUDE.md`). Auto-loads every session.
- `VRA_Next_Phase_Plan.md` → repo root. The week's roadmap.
- `VRA_ClaudeCode_Prompts.md` → keep handy (repo root or elsewhere); you'll paste from it.

> If you're on WSL, put the project on the Linux filesystem (e.g. `~/projects/vra`), not
> under `/mnt/c/...` — it's much faster. Copy the folder in once.

---

## Step 4 — Launch in the project
```
cd "path/to/PFE 2/vra"
claude
```
It reads your directory + `CLAUDE.md` on startup. First thing, sanity-check it sees the layout:
```
> What's the structure of this project and what does CLAUDE.md tell you about it?
```
If that answer looks right, you're wired up correctly.

---

## Step 5 — Run the week
Open `VRA_ClaudeCode_Prompts.md` and paste the **Day 1** block. Work one day per session.
Use `/clear` between days to keep context clean.

---

## The 4 things that make Claude Code work well here

1. **Plan Mode for risky edits.** Press **Shift+Tab** to cycle modes (Normal → auto-accept →
   Plan). In Plan mode it proposes changes without touching files. Use it for the three known
   bugs and any schema change — review the diff, then approve.

2. **Make it run things, not just write them.** It can execute `python run_api.py`, hit
   endpoints, run scripts, read DB rows. Always ask it to *verify with real output*. This is
   its biggest advantage over our chat — it sees what actually happens on your machine.

3. **You own the AI-quality calls.** Claude Code can run the benchmark and show you Qwen's
   output, but whether the recommendations are *good* and the latency *acceptable* is your
   judgment. It's the operator; you're the reviewer.

4. **Commit at the end of each day.** `git commit` after each green day gives you a rollback
   point. If Day 5's multi-upload work goes sideways, you're one `git reset` from safety.

---

## Quick troubleshooting
- `claude doctor` — first stop for any install/env weirdness.
- Ollama unreachable from WSL → confirm `ollama serve` is running on Windows and try
  `curl http://localhost:11434/api/tags` from inside WSL. If blocked, run Claude Code
  natively on Windows instead (Path B).
- Permission errors on npm install → use nvm, never `sudo`.
- It edited something you didn't want → `git checkout -- <file>` (another reason to commit daily).

---

## Sequence at a glance
1. Install Claude Code → `claude doctor`
2. `claude` → authenticate
3. Copy `CLAUDE.md` + `VRA_Next_Phase_Plan.md` into repo root
4. `cd` into the project → `claude` → confirm it sees the structure
5. Paste Day 1 prompt → work day by day → commit each evening
