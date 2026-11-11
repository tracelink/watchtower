(function () {
  "use strict";

  window.wtRuleEditController?.abort();
  const controller = new AbortController();
  window.wtRuleEditController = controller;
  const options = {signal: controller.signal};

  const links = Array.from(document.querySelectorAll("[data-rule-link]"));
  links.forEach((link) => {
    link.dataset.searchName = link.textContent.toLocaleLowerCase();
    link.textContent = link.textContent
      .replace(/([a-z])([A-Z0-9])/g, "$1\u200B$2")
      .replace(/([A-Z])([0-9])/g, "$1\u200B$2")
      .replace(/([0-9])([A-Za-z])/g, "$1\u200B$2");
  });

  const search = document.querySelector("[data-rule-search]");
  const searchStatus = document.querySelector("[data-rule-search-status]");
  const pageStatus = document.querySelector("[data-rule-page-status]");
  const previousPage = document.querySelector("[data-rule-page-previous]");
  const nextPage = document.querySelector("[data-rule-page-next]");
  const kindFilters = Array.from(document.querySelectorAll("[data-rule-kind-filter]"));
  const pageSize = 10;
  let page = 0;
  let activeKind = kindFilters.find((filter) => filter.getAttribute("aria-pressed") === "true")
    ?.dataset.ruleKindFilter || "custom";

  function renderRules() {
    const query = search?.value.trim().toLocaleLowerCase() || "";
    const matches = links.filter((link) => link.dataset.ruleKind === activeKind
      && link.dataset.searchName.includes(query));
    const totalPages = Math.max(1, Math.ceil(matches.length / pageSize));
    page = Math.min(page, totalPages - 1);
    const start = page * pageSize;
    const pageLinks = new Set(matches.slice(start, start + pageSize));
    links.forEach((link) => { link.hidden = !pageLinks.has(link); });
    if (searchStatus) {
      searchStatus.textContent = `${matches.length} ${activeKind} ${matches.length === 1 ? "rule" : "rules"} shown`;
    }
    if (pageStatus) {
      const first = matches.length ? start + 1 : 0;
      const last = matches.length ? Math.min(start + pageSize, matches.length) : 0;
      pageStatus.textContent = `${first}\u2013${last} of ${matches.length}`;
    }
    if (previousPage) previousPage.disabled = page === 0;
    if (nextPage) nextPage.disabled = page + 1 >= totalPages;
    // No pager when there is nothing to page: an empty list or a single page.
    const pager = pageStatus?.closest(".wt-client-pagination");
    if (pager) pager.hidden = matches.length <= pageSize;
  }

  function filterRules() {
    page = 0;
    renderRules();
  }
  search?.addEventListener("input", filterRules, options);
  kindFilters.forEach((filter) => filter.addEventListener("click", () => {
    activeKind = filter.dataset.ruleKindFilter;
    kindFilters.forEach((candidate) => {
      const selected = candidate === filter;
      candidate.setAttribute("aria-pressed", String(selected));
      candidate.classList.toggle("is-active", selected);
    });
    page = 0;
    renderRules();
  }, options));
  previousPage?.addEventListener("click", () => {
    page = Math.max(0, page - 1);
    renderRules();
  }, options);
  nextPage?.addEventListener("click", () => {
    page += 1;
    renderRules();
  }, options);
  const explicitKind = new URLSearchParams(window.location.search).get('kind');
  const selectedLink = links.find(link => link.getAttribute('aria-current') === 'page');
  if (['custom', 'provided'].includes(explicitKind)) activeKind = explicitKind;
  else if (selectedLink) activeKind = selectedLink.dataset.ruleKind;
  else if (!links.some(link => link.dataset.ruleKind === activeKind)) activeKind = links[0]?.dataset.ruleKind || activeKind;
  kindFilters.forEach(filter => { const selected = filter.dataset.ruleKindFilter === activeKind; filter.setAttribute('aria-pressed', String(selected)); filter.classList.toggle('is-active', selected); });
  const initialMatches = links.filter(link => link.dataset.ruleKind === activeKind);
  if (selectedLink && !explicitKind) page = Math.max(0, Math.floor(initialMatches.indexOf(selectedLink) / pageSize));
  renderRules();

  const dialog = document.getElementById("deleteRuleModal");
  document.querySelectorAll('[data-wt-dialog-target="#deleteRuleModal"]').forEach((trigger) => {
    trigger.addEventListener("click", () => {
      const name = trigger.dataset.name;
      document.getElementById("deleteModalContent").textContent =
        `Deleting ${name} removes it from all rulesets. ${trigger.dataset.rulesets} This cannot be undone.`;
      document.getElementById("deleteModalForm").setAttribute("action", trigger.dataset.action);
      document.getElementById("deleteModalInput").value = trigger.dataset.id;
      dialog.show();
    }, options);
  });
  document.getElementById("cancelDeleteRuleModal")?.addEventListener("click", () => dialog.close(), options);
  document.querySelector('[data-wt-dialog-target="#stewardshipModal"]')?.addEventListener("click", () =>
    document.getElementById("stewardshipModal").show(), options);
  document.getElementById("cancelStewardshipModal")?.addEventListener("click", () =>
    document.getElementById("stewardshipModal").close(), options);

  let dirty = false;
  const detail = document.querySelector("[data-rule-detail]");
  const editableForms = Array.from(detail?.querySelectorAll("form:not(#deleteModalForm)") || []);
  const stewardshipForm = document.getElementById("stewardshipForm");
  if (stewardshipForm) editableForms.push(stewardshipForm);
  editableForms.forEach((form) => {
    form.addEventListener("input", () => { dirty = true; }, options);
    form.addEventListener("change", () => { dirty = true; }, options);
    form.addEventListener("submit", () => { dirty = false; }, options);
  });
  window.addEventListener("beforeunload", (event) => {
    if (dirty) {
      event.preventDefault();
      event.returnValue = "";
    }
  }, options);
})();
