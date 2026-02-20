const FAVORITES_STORAGE_KEY = "studiovibi:repo-favorites:v1";

const config = {
  apiBase: "",
  org: "StudioVibi",
  ...(window.STUDIOVIBI_LINKS_CONFIG ?? {})
};

const apiBase = String(config.apiBase || "").replace(/\/+$/, "");
const org = String(config.org || "StudioVibi").trim();

const loginLink = document.querySelector("#login-link");
const authGate = document.querySelector("#auth-gate");
const appShell = document.querySelector("#app-shell");
const topActions = document.querySelector("#top-actions");
const logoutButton = document.querySelector("#logout-button");
const refreshButton = document.querySelector("#refresh-button");
const searchInput = document.querySelector("#search-input");
const statusText = document.querySelector("#status-text");
const repoGrid = document.querySelector("#repo-grid");
const repoCardTemplate = document.querySelector("#repo-card-template");

const state = {
  repos: [],
  favorites: loadFavorites(),
  searchTerm: "",
  authenticated: false,
  user: null
};

function loadFavorites() {
  try {
    const raw = localStorage.getItem(FAVORITES_STORAGE_KEY);
    if (!raw) return new Set();
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return new Set();
    return new Set(parsed.filter((entry) => typeof entry === "string"));
  } catch {
    return new Set();
  }
}

function saveFavorites(favorites) {
  localStorage.setItem(FAVORITES_STORAGE_KEY, JSON.stringify([...favorites]));
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

function setLoggedOutUi() {
  state.authenticated = false;
  state.user = null;
  authGate.hidden = false;
  appShell.hidden = true;
  topActions.hidden = true;
  searchInput.disabled = true;
  searchInput.value = "";
  state.searchTerm = "";
  state.repos = [];
  repoGrid.innerHTML = "";
  setStatus("", "");
}

function setLoggedInUi(user) {
  state.authenticated = true;
  state.user = user;
  authGate.hidden = true;
  appShell.hidden = false;
  topActions.hidden = false;
  searchInput.disabled = false;
}

async function fetchJson(path, init = {}) {
  const response = await fetch(`${apiBase}${path}`, {
    credentials: "include",
    ...init
  });

  let data = null;
  const contentType = response.headers.get("content-type") || "";
  if (contentType.includes("application/json")) {
    data = await response.json();
  } else {
    const text = await response.text();
    data = text ? { error: text } : null;
  }

  if (!response.ok) {
    const message = data?.error || data?.message || `Request failed with status ${response.status}`;
    const error = new Error(message);
    error.status = response.status;
    throw error;
  }

  return data;
}

function repoSort(a, b) {
  const aFavorite = state.favorites.has(a.html_url);
  const bFavorite = state.favorites.has(b.html_url);
  if (aFavorite !== bFavorite) {
    return aFavorite ? -1 : 1;
  }
  return a.name.localeCompare(b.name, undefined, { sensitivity: "base" });
}

function buildEmptyState(text) {
  const empty = document.createElement("div");
  empty.className = "empty-state";
  empty.textContent = text;
  return empty;
}

function formatUpdatedDate(isoDate) {
  if (!isoDate) return "UPDATE: -";
  const parsed = new Date(isoDate);
  if (Number.isNaN(parsed.getTime())) return "UPDATE: -";
  return `UPDATE: ${parsed.toISOString().slice(0, 10)}`;
}

function toggleFavorite(repoUrl) {
  if (state.favorites.has(repoUrl)) {
    state.favorites.delete(repoUrl);
  } else {
    state.favorites.add(repoUrl);
  }
  saveFavorites(state.favorites);
  renderRepos();
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
    const message = term
      ? `Nenhum repositorio encontrado para "${state.searchTerm}".`
      : "Nenhum repositorio disponivel para sua conta.";
    repoGrid.append(buildEmptyState(message));
    return;
  }

  for (const repo of filtered) {
    const fragment = repoCardTemplate.content.cloneNode(true);
    const card = fragment.querySelector(".repo-card");
    const link = fragment.querySelector(".repo-link");
    const name = fragment.querySelector(".repo-name");
    const description = fragment.querySelector(".repo-description");
    const meta = fragment.querySelector(".repo-meta");
    const favoriteButton = fragment.querySelector(".favorite-button");

    link.href = repo.html_url;
    link.setAttribute("aria-label", `Abrir repositorio ${repo.name}`);
    name.textContent = `> ${repo.name}`;
    description.textContent = repo.description || "Sem descricao.";
    meta.textContent = `${repo.private ? "PRIVATE" : "PUBLIC"} | ${formatUpdatedDate(repo.updated_at)}`;

    const isFavorite = state.favorites.has(repo.html_url);
    favoriteButton.textContent = isFavorite ? "★" : "☆";
    favoriteButton.setAttribute("aria-pressed", String(isFavorite));
    favoriteButton.setAttribute(
      "aria-label",
      isFavorite ? `Remover ${repo.name} dos favoritos` : `Favoritar ${repo.name}`
    );

    favoriteButton.addEventListener("click", (event) => {
      event.preventDefault();
      event.stopPropagation();
      toggleFavorite(repo.html_url);
    });

    card.dataset.repoUrl = repo.html_url;
    repoGrid.append(fragment);
  }
}

async function loadRepositories() {
  setStatus("Carregando repositorios...", "");
  const payload = await fetchJson(`/api/repos?org=${encodeURIComponent(org)}`);
  const repos = Array.isArray(payload?.repos) ? payload.repos : [];
  state.repos = repos;
  renderRepos();
  const favoriteCount = repos.filter((repo) => state.favorites.has(repo.html_url)).length;
  setStatus(
    `${repos.length} repositorios carregados para ${org}. Favoritos no topo: ${favoriteCount}.`,
    "ok"
  );
}

async function syncSession() {
  const session = await fetchJson("/api/session");
  if (!session?.authenticated) {
    setLoggedOutUi();
    return;
  }

  setLoggedInUi(session.user ?? null);
  const login = session.user?.login ? ` (${session.user.login})` : "";
  setStatus(`Sessao ativa${login}.`, "ok");
  await loadRepositories();
}

async function handleLogout() {
  try {
    await fetchJson("/auth/logout", { method: "POST" });
    setLoggedOutUi();
  } catch (error) {
    setStatus(error.message || "Falha ao encerrar sessao.", "error");
  }
}

function bindEvents() {
  searchInput.addEventListener("input", () => {
    state.searchTerm = searchInput.value;
    renderRepos();
  });

  logoutButton.addEventListener("click", () => {
    handleLogout();
  });

  refreshButton.addEventListener("click", async () => {
    try {
      await loadRepositories();
    } catch (error) {
      if (error.status === 401) {
        setLoggedOutUi();
        setStatus("Sua sessao expirou. Entre novamente.", "error");
        return;
      }
      setStatus(error.message || "Falha ao atualizar repositorios.", "error");
    }
  });
}

async function init() {
  bindEvents();
  setLoggedOutUi();

  if (!apiBase || apiBase.includes("REPLACE_WITH_WORKER_DOMAIN")) {
    loginLink.hidden = true;
    return;
  }

  loginLink.href = `${apiBase}/auth/login`;

  try {
    await syncSession();
  } catch (error) {
    if (error.status === 401) {
      setLoggedOutUi();
      return;
    }
    setLoggedOutUi();
  }
}

init();
