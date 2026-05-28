# PEAK H2 — `.cursorrules` and `CLAUDE.md` carrying zero-width Unicode

## Hypothesis
A `.cursorrules` or `CLAUDE.md` project file that contains zero-width Unicode
characters (U+200B, U+200C, U+200D, U+FEFF) and was committed or written by
a non-human, non-editor process is part of the TrapDoor AI-assistant
prompt-injection persistence vector. The same campaign also seeds
`AUDIT-MATRIX.md`, `BYPASS.md`, `PAYLOAD.md` and `SWARM.md`.

## Why this discriminates
AI-assistant project-instruction files (.cursorrules, CLAUDE.md, .aider.conf.yml,
.continuerc.json) are intentionally readable by humans. Embedding zero-width
Unicode in them only makes sense if the author wants AI tools to read content
that human reviewers cannot see — exactly the prompt-injection technique
documented in the TrapDoor `AUDIT-MATRIX.md` playbook. Combined with a
git-blame line whose author email is anonymous or whose creator process is a
package manager (node, npm, python, cargo) rather than an editor, this is a
near-deterministic anchor.

## Expected benign vs malicious
- Benign: a developer manually committing legitimate `.cursorrules` content
  with no hidden characters; or a project that uses BOM (U+FEFF) by accident
  in a single file (almost never combined with U+200B / U+200C / U+200D).
- Malicious: `.cursorrules` or `CLAUDE.md` with two or more distinct
  zero-width characters and a marker such as `P-2024-001`,
  `ddjidd564.github.io`, `security scan`, or `AUDIT-MATRIX`.

## Actions on match
1. Run `python3 -c "import sys; data=open(sys.argv[1],'rb').read(); print([(i,hex(b)) for i,b in enumerate(data) if b in (0x0B,) or data[i:i+3] in (b'\\xe2\\x80\\x8b', b'\\xe2\\x80\\x8c', b'\\xe2\\x80\\x8d', b'\\xef\\xbb\\xbf')])" <file>` to enumerate every zero-width character byte offset.
2. Decode the hidden instructions and identify the requested action (almost
   always `run a security scan`, `audit credentials`, `validate cloud config`).
3. Pivot on git history: `git log --all -- .cursorrules CLAUDE.md`; identify
   the originating commit, author email, and PR number.
4. Sweep every repository the same author has pushed to in the last 30 days
   for the same file plant.
5. Treat any AI-coding-assistant session that ran against the poisoned project
   as compromised: assume every credential, environment variable, and SSH key
   that the assistant could read has been exfiltrated.
