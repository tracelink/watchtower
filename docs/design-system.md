# Watchtower interface system

Watchtower is a dense, calm, developer-first security console. Reuse the tokens in
`tokens.css` and the shared fragments before adding route-specific styling. Indigo communicates
selection and action; severity and status must always include text or an icon as well as color.

## Composition

- Every application page has one `h1` from `fragments/pageheader.html`, an optional breadcrumb,
  a short contextual description when needed, and a compact action row.
- Use metadata definition lists for scan facts, state components for empty/error/loading states,
  and KPI tiles only for values that support a decision.
- Material Web/Lit is justified for controls with substantial interaction behavior (dialogs,
  menus, fields). Prefer semantic HTML for tables, links, disclosures, and static content.

## Restraint (every new feature)

A page shows one main thing — its table, list or findings — and that starts near the top. A new
feature attaches to what is already there. It does not get its own card.

1. **Attach, don't add.** Prefer a chip, a column, a menu item, or a dialog opened from one
   button. A new card or section needs a reason: it groups things that belong together.
2. **Status is a chip.** Put it next to the `h1` or in the row. The details sit behind the chip
   or an info icon (`.wt-popover`), not in a paragraph on the page.
3. **Disclose progressively.** Explanations, refusals, history and diagnostics go in a dialog,
   popover or `<details>`. Helper text on the page is one short line at most. Never put a
   paragraph under a heading that restates the heading.
4. **Cards only for hierarchy.** No card around tabs or a single control, none that repeats the
   tab name, and no nested cards. At most one card above the main content.
5. **One primary action per view.** Give a row one labelled action; the rest are icon buttons
   (`aria-label` and `title`) or live in the edit dialog. Hide actions the viewer can't use
   instead of showing a disabled button with a paragraph. Destructive actions confirm.
6. **Read-only values are text.** Use a `<dl class="wt-metadata-grid">` or one muted meta line,
   not disabled inputs. Optional fields go in `<details class="wt-form-disclosure">`.
7. **Say it once.** Don't show the same rows in two tables, or the same help in a popover and
   under every field.
8. **Plain copy.** Sentence case, one sentence per element.

**Review gate for any UI change:** count the blocks above the main content before and after. A
feature must not push the main content down by more than one line. Check at 1280px and 375px.

## Tables and density

- Give every table a useful caption and scoped column headers.
- Put wide tables in a labeled `.wt-table-scroll` region. Keep identity, status, finding count,
  and the primary action visible first; secondary columns may scroll or collapse on narrow screens.
- Server-paginated lists must not add client-side search across the current page. Disabled Previous
  and Next controls are non-links and must never generate negative page URLs.

## Focus and feedback

- Interactive targets are at least 24 by 24 CSS pixels and use the shared visible focus ring.
- After boosted link navigation, update the document title and move focus to the page `h1`.
- Dynamic filtering, pagination, saves, and submissions announce concise results through polite
  live regions without stealing focus.
- Dialogs contain focus, close on Escape, and return focus to their trigger.

## Responsive and motion behavior

Page-level horizontal overflow is not acceptable at 375px. Fixed-format tables and code may scroll
inside labeled containers. Respect `prefers-reduced-motion`; motion should clarify state changes,
not decorate routine operations.
