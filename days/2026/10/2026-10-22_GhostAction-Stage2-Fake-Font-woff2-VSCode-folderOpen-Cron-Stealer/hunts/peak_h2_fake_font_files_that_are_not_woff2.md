# PEAK hunt H2 - Files named as fonts whose content is not a font

## Prepare

**Hypothesis.** A file with a font extension that has no WOFF2 header, or that is readable text, is a disguised script. GhostAction stage 2 hides its stealer in `public/fonts/fa-solid-400.woff2`; the January 2026 Fake Font lure used `fa-brands-regular.woff2` with a leading `try{}catch(err){};` single line.

**Why second.** It confirms or clears the suspicion raised by H1 and also finds payloads that the task file launches from another place.

**Scope.** Repositories on developer machines, your own organisation's repositories on GitHub, and CI workspaces.

**Data quality check first.** Make sure you test the file header (the first four bytes), not the extension. A real WOFF2 starts with the ASCII bytes `wOF2`.

## Execute

```bash
# Author: Jarmi
# Local clones: print every .woff2 whose first four bytes are not "wOF2", with size.
find . -type f -name '*.woff2' -not -path '*/node_modules/*' 2>/dev/null | while read -r f; do
  [ "$(head -c4 "$f" 2>/dev/null)" = "wOF2" ] || echo "NOT-WOFF2 $(wc -c < "$f") $f"; done
```

```bash
# Author: Jarmi
# Organisation repositories: search code for the known file name and list the repositories (needs gh authenticated for the org).
gh search code --owner YOUR_ORG --filename fa-solid-400.woff2 --limit 100
gh search code --owner YOUR_ORG "folderOpen" --filename tasks.json --limit 100
```

## Act

1. Do not open or run the file. Copy it to an isolated analysis host, compute SHA256 and read it as text.
2. Add confirmed hashes to the repository `iocs.csv` and block them in EDR.
3. Remove the file and the task from the repository history only after preserving a copy; then follow the token-first order in H3.
4. Search every developer machine for the same SHA256.

## Knowledge

- Legitimate repositories ship real WOFF2 files, so a header check has very few false positives.
- No public hash exists for the GhostAction stage 2 file in the sources read; this hunt creates the first one for your environment.
