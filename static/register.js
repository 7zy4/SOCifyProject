"use strict";

const registrationError = document.querySelector("[data-registration-error]");
if (registrationError) registrationError.textContent = SOCifyLocale.error(registrationError.dataset.registrationError, registrationError.textContent.trim());

const invitationField = document.getElementById("invitation_token");
const invitationUrl = new URL(window.location.href);
const invitationFragment = new URLSearchParams(invitationUrl.hash.slice(1));
const invitationValue = invitationFragment.get("invitation_token") || invitationUrl.searchParams.get("invitation_token");
if (invitationField && typeof invitationValue === "string" && /^[A-Za-z0-9_-]{32,200}$/.test(invitationValue)) {
  invitationField.value = invitationValue;
  invitationUrl.searchParams.delete("invitation_token");
  if (invitationFragment.has("invitation_token")) invitationUrl.hash = "";
  window.history.replaceState(null, "", invitationUrl.pathname + invitationUrl.search + invitationUrl.hash);
}
