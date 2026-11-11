(function () {
  "use strict";

  const formatter = new Intl.DateTimeFormat(undefined, {
    month: "short",
    day: "2-digit",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    timeZoneName: "short"
  });
  // Lists (data-time-style="short"): "20 Oct, 01:48" this year, "09 Aug 2024, 01:46" before it;
  // the full time is the hover text.
  const shortFormatter = new Intl.DateTimeFormat(undefined, {
    month: "short",
    day: "2-digit",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit"
  });
  const shortThisYearFormatter = new Intl.DateTimeFormat(undefined, {
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit"
  });
  function shortText(millis) {
    const date = new Date(millis);
    const sameYear = date.getFullYear() === new Date().getFullYear();
    return (sameYear ? shortThisYearFormatter : shortFormatter).format(date);
  }

  // Dates on their own (data-time-style="date"): "26 Aug 2026"; the full time is the hover text.
  const dateFormatter = new Intl.DateTimeFormat(undefined, { month: "short", day: "2-digit", year: "numeric" });
  // Lists of people (data-time-style="relative"): "42 min ago", "8 days ago", "17 months ago".
  const relativeFormatter = new Intl.RelativeTimeFormat(undefined, { numeric: "always", style: "long" });
  const MINUTE = 60;
  const HOUR = 60 * MINUTE;
  const DAY = 24 * HOUR;
  // [unit, seconds per unit, used from this age]: days up to two weeks, weeks under two months,
  // months up to two years. 8 days reads "8 days ago", 49 days "7 weeks ago", 520 days
  // "17 months ago".
  const RELATIVE_STEPS = [
    ["year", 365 * DAY, 730 * DAY], ["month", 30 * DAY, 60 * DAY], ["week", 7 * DAY, 14 * DAY],
    ["day", DAY, DAY], ["hour", HOUR, HOUR], ["minute", MINUTE, MINUTE]
  ];
  function relativeText(millis, now) {
    const seconds = Math.round((millis - now) / 1000);
    const age = Math.abs(seconds);
    const step = RELATIVE_STEPS.find(([, , from]) => age >= from);
    if (!step) return "just now";
    return relativeFormatter.format(Math.round(seconds / step[1]), step[0]);
  }

  function localizeTimes(root) {
    const scope = root instanceof Element ? root : document;
    scope.querySelectorAll(".localizetime:not([data-localized])").forEach((element) => {
      // data-millis: the server already printed the time (UTC, same format), so only the zone
      // changes and the text keeps its width. Otherwise the text itself is the epoch millis.
      const raw = element.dataset.millis ?? element.textContent.trim();
      // Epoch millis, or an ISO-8601 time such as a provider's "2026-10-14T12:00:00Z".
      const millis = /^-?\d+$/.test(raw) ? Number(raw) : Date.parse(raw);
      if (!Number.isFinite(millis)) {
        return;
      }
      element.dataset.localized = "true";
      if (millis <= 0) {
        element.textContent = element.dataset.emptyLabel || "Not completed";
        return;
      }
      if (element.dataset.timeStyle === "relative") {
        const full = formatter.format(new Date(millis));
        const note = element.dataset.staleNote;
        element.textContent = relativeText(millis, Date.now());
        element.dataset.tip = note ? full + " · " + note : full;
        element.setAttribute("aria-label", element.textContent + ", " + element.dataset.tip);
        if (!element.hasAttribute("tabindex")) element.tabIndex = 0;
        return;
      }
      if (element.dataset.timeStyle === "date" || element.dataset.timeStyle === "short") {
        const full = formatter.format(new Date(millis));
        element.textContent = element.dataset.timeStyle === "date"
          ? dateFormatter.format(new Date(millis)) : shortText(millis);
        element.dataset.tip = full;
        element.setAttribute("aria-label", full);
        if (!element.hasAttribute("tabindex")) element.tabIndex = 0;
        return;
      }
      element.textContent = formatter.format(new Date(millis));
      element.title = new Date(millis).toISOString() + " · " + Intl.DateTimeFormat().resolvedOptions().timeZone;
    });
    // A chip whose hover text ends in a time (data-tip="Last check passed: " data-tip-millis="…"):
    // the time is appended in the viewer's zone, so the chip itself stays short.
    scope.querySelectorAll("[data-tip-millis]:not([data-tip-localized])").forEach((element) => {
      const millis = Number(element.dataset.tipMillis);
      if (!Number.isFinite(millis) || millis <= 0) {
        return;
      }
      element.dataset.tipLocalized = "true";
      element.dataset.tip = (element.dataset.tip || "") + formatter.format(new Date(millis));
    });
  }

  // UAT #9: one shared format for times that scripts build, the same as server-rendered times.
  window.WatchtowerTime = {
    format: (millis) => formatter.format(new Date(Number(millis))),
    // The list form ("09 Aug 2024, 01:46") for chips and table cells that scripts build.
    short: (millis) => shortText(Number(millis)),
    relative: (millis, now) => relativeText(Number(millis), now === undefined ? Date.now() : Number(now)),
    localize: localizeTimes
  };

  document.addEventListener("DOMContentLoaded", () => localizeTimes(document));
  // outerHTML swaps can leave event.detail.target pointing at the detached pre-swap node.
  // Re-scan the live document; data-localized keeps this idempotent and inexpensive.
  document.addEventListener("htmx:afterSwap", () => localizeTimes(document));
  document.addEventListener("htmx:historyRestore", () => localizeTimes(document));
})();
