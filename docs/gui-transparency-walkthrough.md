# GUI transparency walkthrough (proposal-only)

Manual verification path after the GUI shell redesign. Do **not** export or enable writes unless explicitly approved.

## Connect → tools

1. Open the GUI over HTTPS and sign in as operator.
2. Connect a saved NetScaler or enter NSIP credentials.
3. Confirm the sticky workspace bar shows NSIP/hostname, a write-mode badge (`Proposal only` or `Guarded write enabled`), and catalog freshness.
4. Confirm the hub shows four tool cards; **Regex Rulz** is disabled (Coming soon).

## Analyse application

1. Open **Analyse application**. Browser Lab must **not** appear on this screen.
2. Confirm the four-step stepper: Scan → Findings → Recommend → Export.
3. Start a discovery job (or use an existing completed job).
4. Empty state copy should read: `No scans yet — start with a seed URL above.` when no jobs exist.
5. On a completed job, use **View profile**.
6. Findings should show technologies, routes, signature applicability, and a primary **Review recommended signatures** CTA, plus **Check ADC path** and **Advanced analysis**.
7. **Check ADC path** should render plain-language protection status (for example, AppFW enabled but no policy bound).
8. **Advanced analysis** should populate the analysis panel without leaving the Analyse workspace.

## Recommendations → prepare

1. From Findings or the job row, open signature recommendations.
2. Above the fold: recommended/excluded counts, why panel, and collapsed selection groups.
3. Technology filters live under **Advanced**.
4. Rule rows show title + severity; **Details** expands metadata.
5. Use the sticky footer to **Prepare proposal** (LOG by default).
6. Export stage shows the four-step workflow with a next-step hint. Do not type ENABLE WRITE unless authorized.

## Signature profile / inventory

1. Back to tools → **Create signature profile**.
2. Inventory loads with tabs: Create plan, Catalogs, Existing AppFW, Show vServers.
3. Write-mode safety notice appears at the top.
4. Prepare a guarded plan only; stop before ENABLE WRITE for this walkthrough.

## Positive security lab

1. Back to tools → **Positive security lab** (own entry).
2. Open a guided browser session if a lab target is available.
3. Selection/focus/probe results show structured summaries; JSON is under Advanced.
4. Candidate Accept/Reject status messages appear next to the candidate, not in the browser-lab status line.

## Success checks

- Exclusive tool panels: only one tool visible at a time; Back to tools returns to the hub.
- Write vs proposal mode always visible while connected.
- No orphaned primary actions on completed discovery jobs.
- Inventory does not blank when classic vServers are present (TDZ fix).
