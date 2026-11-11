// Material Web / Lit entry point for Watchtower's Bootstrap -> Material Web migration.
//
// Each import below is side-effectful: it calls customElements.define(...) at module
// evaluation time. Only components actually used by a converted template are listed here
// (never '@material/web/all.js' or similar) so the bundle doesn't ship the byte cost of
// Material components this app never renders. Add one line per new tag name as each wave
// converts more pages - keep this list in sync with grep -roh 'md-[a-z-]+' across templates.

import '@material/web/dialog/dialog.js';
import '@material/web/button/filled-button.js';
import '@material/web/button/text-button.js';
import '@material/web/button/outlined-button.js';
import '@material/web/textfield/outlined-text-field.js';
import '@material/web/checkbox/checkbox.js';
import '@material/web/select/outlined-select.js';
import '@material/web/select/select-option.js';

// App-authored components (Section C: Alpine.js -> Lit interactivity layer), not
// '@material/web/...' imports - the "one import per md-* tag" convention above doesn't apply
// to these; each registers its own 'wt-*' custom element instead.
import './components/wt-theme-toggle.js';
import './components/wt-rail-toggle.js';
import './components/wt-user-menu.js';
import './components/wt-sidebar-nav.js';
import './components/wt-mobile-drawer.js';
import './components/wt-searchable-listbox.js';
import './components/wt-command-palette.js';
