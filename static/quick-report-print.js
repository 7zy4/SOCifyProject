"use strict";

document.addEventListener("DOMContentLoaded", () => {
  const btn = document.getElementById("trigger-print-btn");
  if (btn) {
    btn.addEventListener("click", () => window.print());
  }
  if (new URLSearchParams(window.location.search).get("autoprint") === "1") {
    window.setTimeout(() => window.print(), 250);
  }
});
