"use strict";

document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll(".evidence-table").forEach(table => {
    const headings = [...table.querySelectorAll("thead th")].map(cell => cell.textContent);
    table.querySelectorAll("tbody tr").forEach(row => {
      [...row.cells].forEach((cell, index) => {
        if (cell.colSpan === 1) cell.dataset.label = headings[index] || "";
      });
    });
  });
  const btn = document.getElementById("trigger-print-btn");
  if (btn) {
    btn.addEventListener("click", () => window.print());
  }
  if (new URLSearchParams(window.location.search).get("autoprint") === "1") {
    window.setTimeout(() => window.print(), 250);
  }
});
