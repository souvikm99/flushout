(() => {
  "use strict";

  const app = document.querySelector("#app");
  const SESSION_KEY = "flushout.auth.v1";
  const VERIFIER_KEY = "flushout.pkce.verifier";
  const MAX_TERMINAL_LINES = 2000;
  const state = {
    config: null,
    providers: {},
    auth: null,
    authUser: null,
    profile: null,
    socket: null,
    reconnectTimer: null,
    reconnectAttempt: 0,
    sessions: new Map(),
    selectedSession: null,
    lines: [],
    turnstileToken: null,
    emailNotice: "",
  };

  function element(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  function apiErrorMessage(payload, fallback) {
    return payload?.error?.message || fallback;
  }

  async function request(path, options = {}, auth = true) {
    if (auth) await refreshAuthIfNeeded();
    const headers = new Headers(options.headers || {});
    if (options.body) headers.set("content-type", "application/json");
    if (auth && state.auth?.access_token) headers.set("authorization", `Bearer ${state.auth.access_token}`);
    const response = await fetch(path, { ...options, headers, credentials: "omit" });
    let payload = null;
    try { payload = await response.json(); } catch { /* empty response */ }
    if (!response.ok) throw new Error(apiErrorMessage(payload, `Request failed (${response.status})`));
    return payload;
  }

  function loadAuth() {
    try { state.auth = JSON.parse(sessionStorage.getItem(SESSION_KEY) || "null"); }
    catch { state.auth = null; }
  }

  function saveAuth(auth) {
    const session = auth ? {
      access_token: auth.access_token,
      refresh_token: auth.refresh_token,
      expires_in: Number(auth.expires_in || 3600),
      expires_at: Number(auth.expires_at || (Math.floor(Date.now() / 1000) + Number(auth.expires_in || 3600))),
      token_type: auth.token_type || "bearer",
    } : null;
    state.auth = session;
    if (!session) state.authUser = null;
    if (session) sessionStorage.setItem(SESSION_KEY, JSON.stringify(session));
    else sessionStorage.removeItem(SESSION_KEY);
  }

  function expiresAt(auth) {
    if (auth.expires_at) return Number(auth.expires_at) * 1000;
    return Date.now() + Number(auth.expires_in || 3600) * 1000;
  }

  async function refreshAuthIfNeeded() {
    if (!state.auth) throw new Error("Please sign in");
    if (expiresAt(state.auth) - Date.now() > 60_000) return;
    const response = await fetch(`${state.config.supabase_url}/auth/v1/token?grant_type=refresh_token`, {
      method: "POST",
      headers: { apikey: state.config.supabase_publishable_key, "content-type": "application/json" },
      body: JSON.stringify({ refresh_token: state.auth.refresh_token }),
    });
    if (!response.ok) {
      saveAuth(null);
      throw new Error("Your session expired. Please sign in again.");
    }
    const auth = await response.json();
    auth.expires_at = Math.floor(Date.now() / 1000) + Number(auth.expires_in || 3600);
    saveAuth(auth);
  }

  function randomVerifier() {
    const bytes = new Uint8Array(48);
    crypto.getRandomValues(bytes);
    return bytesToBase64url(bytes);
  }

  function bytesToBase64url(bytes) {
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
  }

  async function loadProviderSettings() {
    try {
      const response = await fetch(`${state.config.supabase_url}/auth/v1/settings`, {
        headers: { apikey: state.config.supabase_publishable_key },
        credentials: "omit",
      });
      if (!response.ok) throw new Error("provider settings unavailable");
      state.providers = (await response.json()).external || {};
    } catch {
      state.providers = {
        github: state.config.github_auth_enabled === true,
        google: state.config.google_auth_enabled === true,
        email: state.config.email_auth_enabled === true,
      };
    }
  }

  function authCallbackUrl() {
    return new URL("/auth/callback", state.config.app_origin).toString();
  }

  async function beginSocialLogin(provider) {
    const verifier = randomVerifier();
    const challenge = bytesToBase64url(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))));
    sessionStorage.setItem(VERIFIER_KEY, verifier);
    const redirect = authCallbackUrl();
    const url = new URL(`${state.config.supabase_url}/auth/v1/authorize`);
    url.searchParams.set("provider", provider);
    url.searchParams.set("redirect_to", redirect);
    url.searchParams.set("code_challenge", challenge);
    url.searchParams.set("code_challenge_method", "s256");
    location.assign(url.toString());
  }

  async function finishAuthCallback() {
    const fragment = new URLSearchParams(location.hash.replace(/^#/u, ""));
    if (fragment.get("error_description")) {
      history.replaceState({}, "", location.pathname);
      throw new Error(fragment.get("error_description"));
    }
    if (fragment.get("access_token") && fragment.get("refresh_token")) {
      saveAuth({
        access_token: fragment.get("access_token"),
        refresh_token: fragment.get("refresh_token"),
        expires_in: Number(fragment.get("expires_in") || 3600),
        expires_at: Math.floor(Date.now() / 1000) + Number(fragment.get("expires_in") || 3600),
        token_type: fragment.get("token_type") || "bearer",
      });
      history.replaceState({}, "", "/dashboard");
      return true;
    }
    const code = new URL(location.href).searchParams.get("code");
    if (!code) return false;
    const verifier = sessionStorage.getItem(VERIFIER_KEY);
    if (!verifier) throw new Error("Sign-in verifier is missing. Start sign-in again.");
    const response = await fetch(`${state.config.supabase_url}/auth/v1/token?grant_type=pkce`, {
      method: "POST",
      headers: { apikey: state.config.supabase_publishable_key, "content-type": "application/json" },
      body: JSON.stringify({ auth_code: code, code_verifier: verifier }),
    });
    if (!response.ok) throw new Error("Could not complete sign-in");
    const auth = await response.json();
    auth.expires_at = Math.floor(Date.now() / 1000) + Number(auth.expires_in || 3600);
    saveAuth(auth);
    sessionStorage.removeItem(VERIFIER_KEY);
    history.replaceState({}, "", "/dashboard");
    return true;
  }

  async function submitEmailAuth(form, mode) {
    const email = form.elements.email.value.trim();
    const password = form.elements.password.value;
    const buttons = form.querySelectorAll("button");
    buttons.forEach((button) => { button.disabled = true; });
    const signup = mode === "signup";
    const endpoint = signup
      ? `${state.config.supabase_url}/auth/v1/signup?redirect_to=${encodeURIComponent(authCallbackUrl())}`
      : `${state.config.supabase_url}/auth/v1/token?grant_type=password`;
    try {
      const response = await fetch(endpoint, {
        method: "POST",
        headers: { apikey: state.config.supabase_publishable_key, "content-type": "application/json" },
        body: JSON.stringify({ email, password }),
        credentials: "omit",
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) {
        const message = signup ? "Account creation failed. Check the email and password requirements." : "Invalid email or password.";
        throw new Error(message);
      }
      if (payload.access_token && payload.refresh_token) {
        payload.expires_at = Math.floor(Date.now() / 1000) + Number(payload.expires_in || 3600);
        saveAuth(payload);
        await loadProfile();
        history.replaceState({}, "", "/dashboard");
        render();
        if (state.profile) connectDashboard();
        return;
      }
      renderSignedOut("Check your email to confirm the account, then return here to sign in.");
    } catch (cause) {
      renderSignedOut(cause.message);
    }
  }

  async function signOut() {
    closeSocket();
    if (state.auth?.access_token) {
      fetch(`${state.config.supabase_url}/auth/v1/logout`, {
        method: "POST",
        headers: { apikey: state.config.supabase_publishable_key, authorization: `Bearer ${state.auth.access_token}` },
      }).catch(() => {});
    }
    saveAuth(null);
    state.profile = null;
    state.authUser = null;
    state.sessions.clear();
    history.replaceState({}, "", "/");
    render();
  }

  function shell(content) {
    app.replaceChildren();
    const header = element("header", "topbar");
    const brand = element("button", "brand");
    brand.type = "button";
    const logo = document.createElement("img");
    logo.className = "brand-logo";
    logo.src = "/assets/flushout-logo.png";
    logo.alt = "";
    brand.append(logo, element("span", "brand-name", "flushout"));
    brand.addEventListener("click", () => { history.pushState({}, "", state.auth ? "/dashboard" : "/"); state.selectedSession = null; render(); });
    header.append(brand);
    if (state.auth) {
      const actions = element("div", "top-actions");
      const privacy = element("span", "privacy-chip", "● not stored");
      const logout = element("button", "button ghost small", "Sign out");
      logout.type = "button";
      logout.addEventListener("click", signOut);
      actions.append(privacy, logout);
      header.append(actions);
    } else {
      const actions = element("nav", "top-actions public-nav");
      actions.setAttribute("aria-label", "Primary navigation");
      const install = element("a", "nav-link", "Install");
      install.href = "#quickstart";
      const how = element("a", "nav-link", "How it works");
      how.href = "#how-it-works";
      const github = element("a", "button ghost small", "GitHub");
      github.href = "https://github.com/souvikm99/flushout";
      github.rel = "noopener noreferrer";
      actions.append(install, how, github);
      header.append(actions);
    }
    app.append(header, content);
  }

  function renderSignedOut(message = "") {
    const main = element("main", "home-page");
    const heroSection = element("section", "landing home-hero");
    const eyebrow = element("p", "eyebrow", "EPHEMERAL BY DESIGN");
    const title = element("h1", "hero");
    title.append("See your Python output ", element("span", "gradient-text", "anywhere."));
    const intro = element("p", "lead", "Private live streaming through Cloudflare. Your output is relayed to your browser and never saved.");
    heroSection.append(eyebrow, title, intro);
    if (message) heroSection.append(element("p", "notice error", message));
    const options = element("section", "auth-options");
    options.setAttribute("aria-label", "Sign in options");
    if (state.providers.github) {
      const github = element("button", "button primary auth-button", "Continue with GitHub");
      github.type = "button";
      github.addEventListener("click", () => beginSocialLogin("github").catch(showFatal));
      options.append(github);
    }
    if (state.providers.google) {
      const google = element("button", "button secondary auth-button", "Continue with Google");
      google.type = "button";
      google.addEventListener("click", () => beginSocialLogin("google").catch(showFatal));
      options.append(google);
    }
    if (state.providers.email) {
      if (options.children.length) options.append(element("p", "auth-divider", "or use email"));
      const form = document.createElement("form");
      form.className = "email-auth-form";
      const email = document.createElement("input");
      email.className = "input";
      email.name = "email";
      email.type = "email";
      email.placeholder = "you@example.com";
      email.autocomplete = "email";
      email.required = true;
      const password = document.createElement("input");
      password.className = "input";
      password.name = "password";
      password.type = "password";
      password.placeholder = "Account password";
      password.autocomplete = "current-password";
      password.minLength = 10;
      password.required = true;
      const actions = element("div", "email-auth-actions");
      const signIn = element("button", "button primary", "Sign in");
      signIn.type = "submit";
      signIn.dataset.mode = "signin";
      const create = element("button", "button ghost", "Create account");
      create.type = "submit";
      create.dataset.mode = "signup";
      actions.append(signIn, create);
      form.append(email, password, actions);
      form.addEventListener("submit", (event) => {
        event.preventDefault();
        submitEmailAuth(form, event.submitter?.dataset.mode || "signin");
      });
      options.append(form);
    }
    if (!options.children.length && message) {
      const retry = element("button", "button secondary auth-button", "Reload sign-in");
      retry.type = "button";
      retry.addEventListener("click", () => location.reload());
      options.append(retry);
    } else if (!options.children.length) {
      options.append(element("p", "notice warning", "No sign-in provider is enabled yet."));
    }
    heroSection.append(options);
    main.append(heroSection, buildHomeContent());
    shell(main);
  }

  function buildHomeContent() {
    const content = element("div", "home-content");

    const quickstart = element("section", "marketing-section quickstart-section");
    quickstart.id = "quickstart";
    const quickCopy = element("div", "section-copy");
    quickCopy.append(
      element("p", "eyebrow", "INSTALL IN SECONDS"),
      element("h2", "marketing-title", "One package. One context manager."),
      element("p", "marketing-lead", "Add Flushout to the Python script you already have. No logging framework, public tunnel, or output storage required."),
    );
    const installCard = element("div", "install-card");
    const installBar = element("div", "install-bar");
    const installCommand = element("code", "install-command", "pip install flushout");
    const copyInstall = element("button", "copy-button", "Copy");
    copyInstall.type = "button";
    copyInstall.addEventListener("click", async () => {
      await navigator.clipboard.writeText("pip install flushout");
      copyInstall.textContent = "Copied";
      setTimeout(() => { copyInstall.textContent = "Copy"; }, 1600);
    });
    installBar.append(installCommand, copyInstall);
    const code = element("pre", "code-card home-code", 'import flushout\n\nwith flushout.stream(name="training-run"):\n    print("Hello from anywhere")');
    installCard.append(installBar, code);
    quickstart.append(quickCopy, installCard);

    const pillars = element("section", "marketing-section");
    const pillarsHead = element("div", "centered-copy");
    pillarsHead.append(element("p", "eyebrow", "BUILT FOR THE MOMENT"), element("h2", "marketing-title", "Live output without a logging project."));
    const featureGrid = element("div", "feature-grid");
    const features = [
      ["01", "Watch from anywhere", "Run Python on one machine and follow its stdout and stderr from your private browser dashboard."],
      ["02", "Nothing to clean up", "Flushout relays output while you are connected. It does not intentionally save stream contents for later."],
      ["03", "Private by default", "A separate streaming password authenticates the producer, while your signed-in account controls browser access."],
    ];
    for (const [number, heading, body] of features) {
      const card = element("article", "feature-card");
      card.append(element("span", "feature-number", number), element("h3", "feature-title", heading), element("p", "muted", body));
      featureGrid.append(card);
    }
    pillars.append(pillarsHead, featureGrid);

    const steps = element("section", "marketing-section steps-section");
    steps.id = "how-it-works";
    const stepsCopy = element("div", "section-copy");
    stepsCopy.append(element("p", "eyebrow", "HOW IT WORKS"), element("h2", "marketing-title", "From terminal to browser in three small steps."), element("p", "marketing-lead", "Flushout stays out of your application architecture. Use it when you need a private, temporary window into a running script."));
    const stepList = element("ol", "step-list");
    const stepItems = [
      ["Create your private access", "Sign in, choose a portal username, and generate a show-once streaming password."],
      ["Wrap the code you want to watch", "Use flushout.stream() around a script, task, training run, or long process."],
      ["Open the live session", "The private URL appears in your terminal and the session shows up in your dashboard."],
    ];
    for (const [heading, body] of stepItems) {
      const item = document.createElement("li");
      item.append(element("h3", "feature-title", heading), element("p", "muted", body));
      stepList.append(item);
    }
    steps.append(stepsCopy, stepList);

    const useCases = element("section", "marketing-section use-cases");
    useCases.append(element("p", "eyebrow", "MADE FOR PYTHON WORK"), element("h2", "marketing-title", "Useful whenever waiting beside a terminal is not."));
    const chips = element("div", "use-case-list");
    for (const label of ["Training runs", "Data jobs", "Automation scripts", "Remote debugging", "Long-running tasks", "Teaching demos"]) chips.append(element("span", "use-case-chip", label));
    useCases.append(chips);

    const finalCta = element("section", "final-cta");
    finalCta.append(element("p", "eyebrow", "READY WHEN YOUR SCRIPT IS"), element("h2", "marketing-title", "Run here. Watch anywhere."), element("p", "marketing-lead", "Install the package, create your private streaming password, and see your next Python run live."));
    const cta = element("button", "button primary", "Get started with Flushout");
    cta.type = "button";
    cta.addEventListener("click", () => window.scrollTo({ top: 0, behavior: "smooth" }));
    finalCta.append(cta);

    const footer = element("footer", "site-footer");
    const footerBrand = element("span", "footer-brand", "flushout");
    const footerLinks = element("div", "footer-links");
    for (const [label, href] of [["PyPI", "https://pypi.org/project/flushout/"], ["GitHub", "https://github.com/souvikm99/flushout"], ["AI guide", "/llms.txt"]]) {
      const link = element("a", "nav-link", label);
      link.href = href;
      footerLinks.append(link);
    }
    footer.append(footerBrand, element("p", "muted", "Private live Python output. Relayed, not recorded."), footerLinks);

    content.append(quickstart, pillars, steps, useCases, finalCta, footer);
    return content;
  }

  function renderOnboarding(message = "") {
    const main = element("main", "center-page");
    const card = element("section", "panel onboarding");
    card.append(element("p", "eyebrow", "ONE-TIME SETUP"), element("h1", "page-title", "Choose your portal username"), element("p", "muted", "You will type this username in the Python prompt. It is not a secret."));
    const form = document.createElement("form");
    form.className = "stack";
    const input = document.createElement("input");
    input.className = "input";
    input.name = "username";
    input.placeholder = "souvik_99";
    input.pattern = "[a-z0-9_]{3,32}";
    input.minLength = 3;
    input.maxLength = 32;
    input.required = true;
    input.autocomplete = "username";
    const submit = element("button", "button primary", "Create dashboard");
    submit.type = "submit";
    form.append(input, submit);
    if (message) form.prepend(element("p", "notice error", message));
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      submit.disabled = true;
      try {
        const result = await request("/api/v1/profile/username", { method: "POST", body: JSON.stringify({ username: input.value }) });
        state.profile = result.profile;
        render();
        connectDashboard();
      } catch (cause) { renderOnboarding(cause.message); }
    });
    card.append(form);
    main.append(card);
    shell(main);
    input.focus();
  }

  function passwordPanel() {
    const panel = element("section", "panel password-panel");
    const header = element("div", "panel-heading");
    const copy = element("div");
    copy.append(element("h2", "section-title", "Streaming password"), element("p", "muted", state.profile.has_stream_password ? "Configured. Rotate it if it may have leaked." : "Generate this before using the Python package."));
    const button = element("button", "button secondary", state.profile.has_stream_password ? "Rotate" : "Generate");
    button.type = "button";
    if (state.config.turnstile_site_key) button.disabled = !state.turnstileToken;
    button.addEventListener("click", () => generateStreamPassword(button));
    header.append(copy, button);
    panel.append(header);
    if (state.config.turnstile_site_key) {
      const challenge = element("div", "turnstile-box");
      challenge.id = "turnstile-password";
      panel.append(challenge);
    }
    if (state.profile.has_stream_password) {
      const revoke = element("button", "button danger small", "Revoke streaming password");
      revoke.type = "button";
      revoke.addEventListener("click", async () => {
        if (!confirm("Revoke the streaming password? New streams will stop authenticating.")) return;
        await request("/api/v1/profile/stream-password", { method: "DELETE" });
        state.profile.has_stream_password = false;
        render();
      });
      panel.append(revoke);
    }
    return panel;
  }

  function notificationEmailPanel() {
    const panel = element("section", "panel email-panel");
    const verified = Boolean(state.authUser?.email && (state.authUser.email_confirmed_at || state.authUser.confirmed_at));
    panel.append(
      element("h2", "section-title", "Completion notifications"),
      element("p", "muted", verified
        ? `Verified email: ${state.authUser.email}. The Python package can email a minimal success or failure summary when you opt in.`
        : "Add and verify an email address before the Python package can send completion notifications. This is required when GitHub does not provide an email."),
    );
    if (state.emailNotice) panel.append(element("p", "notice warning", state.emailNotice));
    if (verified) return panel;

    const form = document.createElement("form");
    form.className = "email-profile-form";
    const email = document.createElement("input");
    email.className = "input";
    email.type = "email";
    email.name = "email";
    email.placeholder = "you@example.com";
    email.autocomplete = "email";
    email.required = true;
    email.value = state.authUser?.email || "";
    const submit = element("button", "button secondary", state.authUser?.email ? "Resend verification" : "Add email");
    submit.type = "submit";
    form.append(email, submit);
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      submit.disabled = true;
      try {
        const response = await fetch(`${state.config.supabase_url}/auth/v1/user?redirect_to=${encodeURIComponent(authCallbackUrl())}`, {
          method: "PUT",
          headers: {
            apikey: state.config.supabase_publishable_key,
            authorization: `Bearer ${state.auth.access_token}`,
            "content-type": "application/json",
          },
          body: JSON.stringify({ email: email.value.trim() }),
          credentials: "omit",
        });
        const payload = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(payload.msg || payload.message || "Could not update email");
        state.authUser = payload;
        state.emailNotice = "Check your inbox and verify the address, then return and reload this page.";
        render();
      } catch (cause) {
        state.emailNotice = cause.message;
        render();
      }
    });
    panel.append(form);
    return panel;
  }

  async function generateStreamPassword(button) {
    if (state.profile.has_stream_password && !confirm("Rotate the password? The old password will stop working.")) return;
    button.disabled = true;
    try {
      const payload = await request("/api/v1/profile/stream-password", { method: "POST", body: JSON.stringify({ turnstile_token: state.turnstileToken }) });
      state.turnstileToken = null;
      state.profile.has_stream_password = true;
      renderPasswordReveal(payload.stream_password);
    } catch (cause) { alert(cause.message); button.disabled = false; }
  }

  function renderPasswordReveal(password) {
    const main = element("main", "center-page");
    const card = element("section", "panel reveal");
    card.append(element("p", "eyebrow", "SHOWN ONCE"), element("h1", "page-title", "Save your streaming password"), element("p", "notice warning", "It cannot be recovered. Save it in a password manager, then close this screen."));
    const secret = element("code", "secret", password);
    const copy = element("button", "button primary", "Copy password");
    copy.type = "button";
    copy.addEventListener("click", async () => { await navigator.clipboard.writeText(password); copy.textContent = "Copied"; });
    const done = element("button", "button ghost", "I saved it");
    done.type = "button";
    done.addEventListener("click", () => { render(); connectDashboard(); });
    card.append(secret, copy, done);
    main.append(card);
    shell(main);
  }

  function renderSessionList() {
    const section = element("section", "sessions-section");
    const heading = element("div", "section-heading");
    heading.append(element("div", "live-dot"), element("h2", "section-title", "Active sessions"), element("span", "count", String(state.sessions.size)));
    section.append(heading);
    const grid = element("div", "session-grid");
    if (state.sessions.size === 0) {
      const empty = element("div", "empty");
      empty.append(element("div", "empty-icon", ">_"), element("h3", "", "No active streams"), element("p", "muted", "Run a Python script with flushout.stream() and it will appear here automatically."));
      grid.append(empty);
    } else {
      for (const session of state.sessions.values()) {
        const card = element("button", "session-card");
        card.type = "button";
        card.append(element("span", "live-pill", "LIVE"), element("strong", "session-card-name", session.name), element("span", "session-time", new Date(session.started_at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })));
        card.addEventListener("click", () => selectSession(session.id));
        grid.append(card);
      }
    }
    section.append(grid);
    return section;
  }

  function renderDashboard() {
    const main = element("main", "dashboard container");
    const welcome = element("section", "welcome");
    const copy = element("div");
    copy.append(element("p", "eyebrow", `@${state.profile.username}`), element("h1", "page-title", "Live workspace"), element("p", "muted", "Output exists only while connected. Nothing is recorded."));
    const connection = element("span", "connection", state.socket?.readyState === WebSocket.OPEN ? "Connected" : "Connecting");
    connection.id = "connection-state";
    welcome.append(copy, connection);
    main.append(welcome, passwordPanel(), notificationEmailPanel(), renderSessionList());
    shell(main);
    setupTurnstile();
  }

  function setupTurnstile() {
    const container = document.querySelector("#turnstile-password");
    if (!container || !state.config.turnstile_site_key) return;
    if (!window.turnstile) {
      setTimeout(setupTurnstile, 250);
      return;
    }
    window.turnstile.render(container, {
      sitekey: state.config.turnstile_site_key,
      action: "stream-password",
      theme: "dark",
      callback: (token) => {
        state.turnstileToken = token;
        const button = document.querySelector(".password-panel .button.secondary");
        if (button) button.disabled = false;
      },
      "expired-callback": () => { state.turnstileToken = null; },
      "error-callback": () => { state.turnstileToken = null; },
    });
  }

  function renderTerminal() {
    const session = state.sessions.get(state.selectedSession) || { name: "Live session", id: state.selectedSession };
    const main = element("main", "terminal-page container");
    const bar = element("div", "terminal-bar");
    const back = element("button", "button ghost small", "← Sessions");
    back.type = "button";
    back.addEventListener("click", () => { if (state.socket?.readyState === WebSocket.OPEN) state.socket.send(JSON.stringify({ type: "unsubscribe" })); state.selectedSession = null; state.lines = []; history.pushState({}, "", "/dashboard"); render(); });
    const title = element("div", "terminal-heading");
    title.append(element("strong", "", session.name), element("span", "live-pill", "LIVE · NOT SAVED"));
    bar.append(back, title);
    const terminal = element("section", "terminal");
    terminal.id = "terminal-output";
    terminal.setAttribute("role", "log");
    terminal.setAttribute("aria-live", "off");
    if (state.lines.length === 0) terminal.append(element("p", "terminal-hint", "Connected. Only new output will appear here—earlier output is not stored."));
    else for (const line of state.lines) appendRenderedLine(terminal, line);
    main.append(bar, terminal);
    shell(main);
  }

  function appendRenderedLine(terminal, line) {
    const row = element("div", `terminal-line ${line.stream || "mixed"}`);
    row.textContent = line.content;
    terminal.append(row);
  }

  function appendOutput(message) {
    if (message.session_id !== state.selectedSession) return;
    const chunks = message.content.split(/(?<=\n)/u);
    for (const content of chunks) {
      if (!content) continue;
      state.lines.push({ content, stream: message.stream });
    }
    if (state.lines.length > MAX_TERMINAL_LINES) {
      state.lines.splice(0, state.lines.length - MAX_TERMINAL_LINES);
      state.lines.unshift({ content: "[flushout: older browser-only lines removed]\n", stream: "system" });
      renderTerminal();
      return;
    }
    const terminal = document.querySelector("#terminal-output");
    if (!terminal) return;
    terminal.querySelector(".terminal-hint")?.remove();
    for (const content of chunks) if (content) appendRenderedLine(terminal, { content, stream: message.stream });
    terminal.scrollTop = terminal.scrollHeight;
  }

  function selectSession(id) {
    if (!state.sessions.has(id)) return;
    state.selectedSession = id;
    state.lines = [];
    history.pushState({}, "", `/live/${id}`);
    render();
    if (state.socket?.readyState === WebSocket.OPEN) state.socket.send(JSON.stringify({ type: "subscribe", session_id: id }));
  }

  function wsUrl(path) {
    const url = new URL(path, location.origin);
    url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
    return url.toString();
  }

  async function connectDashboard() {
    if (!state.auth || !state.profile || state.socket?.readyState === WebSocket.OPEN || state.socket?.readyState === WebSocket.CONNECTING) return;
    clearTimeout(state.reconnectTimer);
    try {
      const payload = await request("/api/v1/dashboard-ticket", { method: "POST" });
      const socket = new WebSocket(wsUrl("/api/v1/dashboard"), ["flushout.v1", `ticket.${payload.ticket}`]);
      state.socket = socket;
      socket.addEventListener("open", () => {
        state.reconnectAttempt = 0;
        const indicator = document.querySelector("#connection-state");
        if (indicator) indicator.textContent = "Connected";
        if (state.selectedSession) socket.send(JSON.stringify({ type: "subscribe", session_id: state.selectedSession }));
      });
      socket.addEventListener("message", (event) => handleSocketMessage(event.data));
      socket.addEventListener("close", () => scheduleReconnect());
      socket.addEventListener("error", () => socket.close());
    } catch { scheduleReconnect(); }
  }

  function handleSocketMessage(raw) {
    let message;
    try { message = JSON.parse(raw); } catch { return; }
    if (message.type === "sessions") {
      state.sessions = new Map(message.items.map((item) => [item.id, item]));
      const pathSession = location.pathname.match(/^\/live\/([0-9a-f-]{36})$/u)?.[1];
      if (pathSession && state.sessions.has(pathSession)) state.selectedSession = pathSession;
      render();
      if (state.selectedSession) state.socket.send(JSON.stringify({ type: "subscribe", session_id: state.selectedSession }));
    } else if (message.type === "session_started") {
      state.sessions.set(message.session.id, message.session);
      if (!state.selectedSession) render();
    } else if (message.type === "session_ended") {
      state.sessions.delete(message.session_id);
      if (state.selectedSession === message.session_id) {
        document.querySelector(".terminal-heading .live-pill")?.replaceChildren("ENDED · NOT SAVED");
      } else render();
    } else if (message.type === "output") appendOutput(message);
    else if (message.type === "session_unavailable" && state.selectedSession === message.session_id) {
      state.selectedSession = null;
      history.replaceState({}, "", "/dashboard");
      render();
    }
  }

  function scheduleReconnect() {
    state.socket = null;
    if (!state.auth) return;
    const indicator = document.querySelector("#connection-state");
    if (indicator) indicator.textContent = "Reconnecting";
    const delay = Math.min(30_000, 1000 * (2 ** state.reconnectAttempt++)) + Math.floor(Math.random() * 500);
    state.reconnectTimer = setTimeout(connectDashboard, delay);
  }

  function closeSocket() {
    clearTimeout(state.reconnectTimer);
    if (state.socket) state.socket.close(1000, "signed out");
    state.socket = null;
  }

  async function loadProfile() {
    try { state.profile = (await request("/api/v1/profile")).profile; }
    catch (cause) {
      if (/sign|session|unauthorized/iu.test(cause.message)) saveAuth(null);
      else throw cause;
    }
  }

  async function loadAuthUser() {
    const response = await fetch(`${state.config.supabase_url}/auth/v1/user`, {
      headers: { apikey: state.config.supabase_publishable_key, authorization: `Bearer ${state.auth.access_token}` },
      credentials: "omit",
      cache: "no-store",
    });
    if (!response.ok) throw new Error("Could not load your account email");
    state.authUser = await response.json();
  }

  function render() {
    if (!state.auth) return renderSignedOut();
    if (location.pathname === "/" || location.pathname === "/dashbord") history.replaceState({}, "", "/dashboard");
    if (!state.profile) return renderOnboarding();
    if (state.selectedSession) return renderTerminal();
    renderDashboard();
  }

  function showFatal(cause) {
    closeSocket();
    renderSignedOut(cause?.message || "Something went wrong");
  }

  window.addEventListener("popstate", () => {
    if (location.pathname === "/dashbord") history.replaceState({}, "", "/dashboard");
    const id = location.pathname.match(/^\/live\/([0-9a-f-]{36})$/u)?.[1] || null;
    state.selectedSession = id;
    render();
    if (id && state.socket?.readyState === WebSocket.OPEN) state.socket.send(JSON.stringify({ type: "subscribe", session_id: id }));
  });

  (async () => {
    try {
      state.config = await request("/api/v1/config", { cache: "no-store" }, false);
      await loadProviderSettings();
      loadAuth();
      await finishAuthCallback();
      if (location.pathname === "/dashbord") history.replaceState({}, "", "/dashboard");
      if (state.auth) {
        await loadProfile();
        if (state.auth) await loadAuthUser();
      }
      const pathSession = location.pathname.match(/^\/live\/([0-9a-f-]{36})$/u)?.[1];
      if (pathSession) state.selectedSession = pathSession;
      render();
      if (state.auth && state.profile) connectDashboard();
    } catch (cause) { showFatal(cause); }
  })();
})();
