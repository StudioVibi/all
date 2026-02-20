const DEFAULT_ORG = "StudioVibi";
const FAVORITES_STORAGE_KEY = "studiovibi:all:favorites:v1";

const authButton = document.querySelector("#auth-button");
const searchInput = document.querySelector("#search-input");
const statusText = document.querySelector("#status-text");
const repoGrid = document.querySelector("#repo-grid");
const repoCardTemplate = document.querySelector("#repo-card-template");

const state = {
  repos: [],
  favorites: loadFavorites(),
  searchTerm: "",
  org: DEFAULT_ORG,
  session: {
    authenticated: false,
    user: null,
    oauthConfigured: false
  },
  visibilityMode: "public_only"
};

function loadFavorites() {
  try {
    const raw = localStorage.getItem(FAVORITES_STORAGE_KEY);
    if (!raw) return new Set();
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return new Set();
    return new Set(parsed.filter((value) => typeof value === "string"));
  } catch {
    return new Set();
  }
}

function saveFavorites() {
  localStorage.setItem(FAVORITES_STORAGE_KEY, JSON.stringify([...state.favorites]));
}

function normalize(value) {
  return String(value || "").toLowerCase().trim();
}

function setStatus(message, status = "") {
  statusText.textContent = message;
  if (status) {
    statusText.dataset.state = status;
  } else {
    delete statusText.dataset.state;
  }
}

async function fetchJson(path, init = {}) {
  const response = await fetch(path, {
    credentials: "include",
    ...init
  });

  let payload = null;
  const contentType = response.headers.get("content-type") || "";
  if (contentType.includes("application/json")) {
    payload = await response.json();
  } else {
    const text = await response.text();
    payload = text ? { error: text } : null;
  }

  if (!response.ok) {
    const message = payload?.error || payload?.message || `Request failed (${response.status})`;
    const error = new Error(message);
    error.status = response.status;
    throw error;
  }

  return payload;
}

function buildEmptyState(message) {
  const empty = document.createElement("div");
  empty.className = "empty-state";
  empty.textContent = message;
  return empty;
}

function toggleFavorite(repoUrl) {
  if (state.favorites.has(repoUrl)) {
    state.favorites.delete(repoUrl);
  } else {
    state.favorites.add(repoUrl);
  }
  saveFavorites();
}

function repoSort(a, b) {
  const aFavorite = state.favorites.has(a.html_url);
  const bFavorite = state.favorites.has(b.html_url);
  if (aFavorite !== bFavorite) {
    return aFavorite ? -1 : 1;
  }
  return a.name.localeCompare(b.name, undefined, { sensitivity: "base" });
}

function renderRepos() {
  repoGrid.innerHTML = "";
  const term = normalize(state.searchTerm);
  const filtered = state.repos
    .filter((repo) => {
      if (!term) return true;
      return normalize(repo.name).includes(term) || normalize(repo.description).includes(term);
    })
    .sort(repoSort);

  if (filtered.length === 0) {
    if (state.repos.length === 0) {
      repoGrid.append(buildEmptyState("Nenhum repositorio encontrado para esta organizacao."));
      return;
    }

    repoGrid.append(buildEmptyState(`Nenhum repositorio encontrado para "${state.searchTerm}".`));
    return;
  }

  for (const repo of filtered) {
    const fragment = repoCardTemplate.content.cloneNode(true);
    const link = fragment.querySelector(".repo-link");
    const name = fragment.querySelector(".repo-name");
    const description = fragment.querySelector(".repo-description");
    const meta = fragment.querySelector(".repo-meta");
    const favoriteButton = fragment.querySelector(".favorite-button");
    const favoriteIcon = fragment.querySelector(".favorite-button i");

    link.href = repo.html_url;
    link.setAttribute("aria-label", `Abrir repositorio ${repo.name}`);
    name.textContent = repo.name;
    description.textContent = repo.description || "Sem descricao.";
    meta.textContent = repo.private ? "PRIVATE" : "PUBLIC";

    const isFavorite = state.favorites.has(repo.html_url);
    favoriteButton.setAttribute("aria-pressed", String(isFavorite));
    favoriteButton.setAttribute(
      "aria-label",
      isFavorite ? `Remover ${repo.name} dos favoritos` : `Favoritar ${repo.name}`
    );
    favoriteIcon.className = isFavorite ? "fa-solid fa-star" : "fa-regular fa-star";

    favoriteButton.addEventListener("click", (event) => {
      event.preventDefault();
      event.stopPropagation();
      toggleFavorite(repo.html_url);
      renderRepos();
    });

    repoGrid.append(fragment);
  }
}

function renderAuthButton() {
  const { authenticated, user, oauthConfigured } = state.session;
  authButton.disabled = !oauthConfigured && !authenticated;

  if (authenticated) {
    const login = user?.login ? ` @${user.login}` : "";
    authButton.textContent = `logout${login}`;
    authButton.setAttribute("aria-label", "Encerrar sessao do GitHub");
    return;
  }

  authButton.textContent = "login";
  authButton.setAttribute("aria-label", "Entrar com GitHub");

  if (!oauthConfigured) {
    authButton.title = "OAuth do GitHub nao configurado no servidor.";
  } else {
    authButton.removeAttribute("title");
  }
}

function getErrorMessageFromUrl() {
  const url = new URL(window.location.href);
  const error = url.searchParams.get("error");
  if (!error) return "";

  const messages = {
    oauth_not_configured: "OAuth do GitHub nao configurado no servidor.",
    oauth_missing_code: "Falha no retorno do GitHub (codigo ausente).",
    oauth_state_invalid: "Falha de seguranca no login. Tente novamente.",
    oauth_state_expired: "Tentativa de login expirada. Tente novamente.",
    oauth_failed: "Nao foi possivel concluir o login com GitHub."
  };

  const message = messages[error] || "Falha no login com GitHub.";
  url.searchParams.delete("error");
  window.history.replaceState({}, document.title, url.toString());
  return message;
}

async function syncSession() {
  const payload = await fetchJson("/api/session");
  state.session.authenticated = Boolean(payload?.authenticated);
  state.session.user = payload?.user || null;
  state.session.oauthConfigured = Boolean(payload?.oauth_configured);
}

async function loadRepositories() {
  const payload = await fetchJson(`/api/repos?org=${encodeURIComponent(state.org)}`);
  state.repos = Array.isArray(payload?.repos) ? payload.repos : [];
  state.visibilityMode =
    payload?.visibility_mode === "public_and_private" ? "public_and_private" : "public_only";
}

async function handleAuthButtonClick() {
  if (state.session.authenticated) {
    try {
      await fetchJson("/auth/logout", { method: "POST" });
      await syncSession();
      await loadRepositories();
      renderAuthButton();
      renderRepos();
      setStatus("Sessao encerrada. Exibindo apenas repositorios publicos.", "ok");
    } catch (error) {
      setStatus(error.message || "Falha ao encerrar sessao.", "error");
    }
    return;
  }

  if (!state.session.oauthConfigured) {
    setStatus("OAuth do GitHub nao configurado no servidor.", "error");
    return;
  }

  window.location.href = "/auth/login";
}

function bindEvents() {
  authButton.addEventListener("click", () => {
    handleAuthButtonClick();
  });

  searchInput.addEventListener("input", () => {
    state.searchTerm = searchInput.value;
    renderRepos();
  });
}

async function init() {
  bindEvents();

  const oauthError = getErrorMessageFromUrl();
  if (oauthError) {
    setStatus(oauthError, "error");
  } else {
    setStatus("Carregando repositorios...", "");
  }

  try {
    await syncSession();
    await loadRepositories();

    renderAuthButton();
    renderRepos();
    setStatus("", "");
  } catch (error) {
    renderAuthButton();
    renderRepos();
    setStatus(error.message || "Falha ao carregar repositorios.", "error");
  }
}

init();
