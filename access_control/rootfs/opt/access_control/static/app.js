(() => {
  "use strict";

  // Preserve the existing ingress-aware helper for the few page-specific
  // handlers that build absolute URLs. <base href> is always scoped to either
  // the HA Ingress prefix or /, so it is the single source of truth.
  const basePath = new URL(document.baseURI).pathname.replace(/\/$/, "");
  window.__INGRESS_PREFIX__ = basePath;

  function csrfToken() {
    return document.querySelector('meta[name="csrf-token"]')?.content || "";
  }

  function injectCsrf(root = document) {
    const token = csrfToken();
    if (!token) return;

    root.querySelectorAll('form[method="post"]').forEach((form) => {
      if (form.querySelector('input[name="_csrf_token"]')) return;

      const input = document.createElement("input");
      input.type = "hidden";
      input.name = "_csrf_token";
      input.value = token;
      form.appendChild(input);
    });
  }

  function updateCsrfToken(nextDocument) {
    const next = nextDocument.querySelector('meta[name="csrf-token"]');
    const current = document.querySelector('meta[name="csrf-token"]');
    if (next && current) current.content = next.content;
  }

  injectCsrf();

  // Global submit-disable: once a form is really submitting, disable its submit
  // button, dim it, and swap its label so a double-tap can't fire the action
  // twice. The document-level bubble listener runs AFTER any inline onsubmit, so
  // event.defaultPrevented being set means a confirm() dialog said "no" and we
  // leave the button alone. CSRF hidden inputs are injected at load, unaffected.
  document.addEventListener("submit", (event) => {
    if (event.defaultPrevented) return;
    const button = event.target.querySelector(
      'button[type="submit"], button:not([type]), input[type="submit"]',
    );
    if (!button || button.disabled) return;
    button.disabled = true;
    button.style.opacity = "0.6";
    const pending = button.dataset.pendingText || "Working…";
    if (button.tagName === "INPUT") {
      button.value = pending;
    } else {
      button.textContent = pending;
    }
  });

  const refreshHook = document.querySelector("[data-background-refresh]");
  if (!refreshHook) return;

  const configuredInterval = Number.parseInt(
    refreshHook.dataset.backgroundRefresh,
    10,
  );
  const interval = Number.isFinite(configuredInterval)
    ? Math.max(configuredInterval, 1000)
    : 10000;
  const refreshUrl = refreshHook.dataset.backgroundRefreshUrl || ".";
  const targetSelector =
    refreshHook.dataset.backgroundRefreshTarget || ".auto-refresh";

  async function refresh() {
    try {
      if (document.visibilityState !== "hidden" && refreshHook.isConnected) {
        const response = await fetch(new URL(refreshUrl, document.baseURI), {
          method: "GET",
          credentials: "same-origin",
          cache: "no-store",
          headers: {
            Accept: "text/html",
            "X-Background-Poll": "true",
          },
        });

        if (response.redirected) {
          window.location.assign(response.url);
          return;
        }

        if (response.ok) {
          const nextDocument = new DOMParser().parseFromString(
            await response.text(),
            "text/html",
          );
          const currentTarget = document.querySelector(targetSelector);
          const nextTarget = nextDocument.querySelector(targetSelector);

          if (currentTarget && nextTarget) {
            updateCsrfToken(nextDocument);
            currentTarget.replaceWith(nextTarget);
            injectCsrf(nextTarget);
          }
        }
      }
    } catch (_error) {
      // A transient network error is expected during HA/add-on restarts. The
      // next scheduled poll retries without disrupting the current page.
    } finally {
      window.setTimeout(refresh, interval);
    }
  }

  window.setTimeout(refresh, interval);
})();
