# GUI transparency + protection lifecycle walkthrough (proposal-only)

Manual verification path after the GUI shell redesign and competitive lifecycle tranche. Do **not** export or enable writes unless explicitly approved.

## Connect → tools

1. Open the GUI over HTTPS and sign in as operator.
2. Connect a saved NetScaler or enter NSIP credentials.
3. Confirm the sticky workspace bar shows NSIP/hostname, a write-mode badge (`Proposal only` or `Guarded write enabled`), and catalog freshness.
4. Confirm the hub shows four tool cards: Analyse application, Create signature profile, Positive security lab, and **Regex Rulz** (enabled).

## Analyse application

1. Open **Analyse application**. Browser Lab must **not** appear on this screen.
2. Confirm the four-step stepper: Scan → Findings → Recommend → Export.
3. Start a discovery job (or use an existing completed job).
4. Empty state copy should read: `No scans yet — start with a seed URL above.` when no jobs exist.
5. On a completed job, use **View profile**.
6. Findings should show technologies, routes, signature applicability, a primary **Review recommended signatures** CTA, **Check ADC path**, **Advanced analysis**, and **Open Regex Rulz**. Advanced path-regex drafts remain under **Advanced · Prepare path regex drafts**.
7. **Check ADC path** should render plain-language protection status. When AppFW is enabled with no policy binding, the primary CTA is **Bind LOG protection** (with Review signatures as secondary).
8. **Advanced analysis** should populate the analysis panel without leaving the Analyse workspace.

## Recommendations → prepare

1. From Findings or the job row, open signature recommendations.
2. Above the fold: recommended/excluded counts, why panel, and **Protection intents** cards with Select/Deselect intent.
3. Intent cards sit above the expandable group/subgroup/rule tree; the `selected_rule_ids` contract is unchanged.
4. Technology filters live under **Advanced**.
5. Rule rows show title + severity; **Details** expands metadata.
6. Use the sticky footer to **Prepare proposal** (LOG by default).
7. Export stage shows the four-step workflow with a next-step hint. Do not type ENABLE WRITE unless authorized.

## After export — protection status + bind

1. On an **exported** custom signature set, use **Open protection status**.
2. Confirm object name, LOG/BLOCK action, binding state, bound vServers, and hit counters (or the soft notice when hits are unavailable).
3. Operator actions: **Keep LOG**, **Prepare BLOCK promotion**, **Prepare exception**, and **Bind LOG protection** when unbound.
4. Promotion/exception create new gated drafts — still approval → preflight → `ENABLE WRITE`.
5. Bind wizard: choose base profile, destination name, optional policy name, and LB vServer, then **Prepare bind plan** (reuses duplicate/create plan APIs).

## Regex Rulz

1. Hub → **Regex Rulz**, or Findings → **Open Regex Rulz**.
2. Select a completed discovery job (defaults to the current Findings job when set).
3. Choose Basic / Balanced / Aggressive; copy patterns. Proposal-only — no ADC write from this workspace.

## Signature profile / inventory

1. Back to tools → **Create signature profile**.
2. Inventory loads with tabs: Create plan, Catalogs, Existing AppFW, Show vServers.
3. Write-mode safety notice appears at the top.
4. Job-scoped bind from Analyse is preferred after export; inventory Create plan remains for ad-hoc work.
5. Prepare a guarded plan only; stop before ENABLE WRITE for this walkthrough.

## Positive security lab

1. Back to tools → **Positive security lab** (own entry).
2. Open a guided browser session if a lab target is available.
3. Selection/focus/probe results show structured summaries; JSON is under Advanced.
4. Saved candidates expose a **structured endpoint editor** (method, path template, decision_mode) and **Compile observe-only preview**.
5. Compile preview is metadata-only: `enforcement_mode=observe`, `positive_model_enabled=false`, no BLOCK/ADC write.
6. Candidate Accept/Reject status messages appear next to the candidate, not in the browser-lab status line.

## Success checks

- Exclusive tool panels: only one tool visible at a time; Back to tools returns to the hub.
- Write vs proposal mode always visible while connected.
- Operator can export LOG signatures, bind them to the matched vServer, refresh hit counts, and prepare gated BLOCK promotion or exception without leaving Analyse.
- “AppFW enabled, no policy” findings always offer **Bind LOG protection** as the next action.
- No change to proposal-only default or approval/preflight/`ENABLE WRITE` semantics.
- Inventory does not blank when classic vServers are present (TDZ fix).
