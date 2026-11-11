(function () {
  "use strict";

  function addPathBreaks(root) {
    const scope = root instanceof Element ? root : document;
    scope.querySelectorAll("table.datatable td:not([data-path-wrapped])").forEach((cell) => {
      if (cell.querySelector(".wt-code-snippet")) {
        return;
      }
      const walker = document.createTreeWalker(cell, NodeFilter.SHOW_TEXT);
      const textNodes = [];
      while (walker.nextNode()) {
        textNodes.push(walker.currentNode);
      }
      textNodes.forEach((node) => {
        node.nodeValue = node.nodeValue.replace(/\//g, "/\u200B");
      });
      cell.dataset.pathWrapped = "true";
    });
  }

  document.addEventListener("DOMContentLoaded", () => addPathBreaks(document));
  document.addEventListener("htmx:afterSwap", (event) => addPathBreaks(event.detail.target));
})();
