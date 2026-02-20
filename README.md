# StudioVibi Repositories Catalog (`/all`)

Implementacao da pagina `studiovibi.github.io/all` com:

- login GitHub para listar repositorios publicos e privados acessiveis pelo usuario
- grid de cards (6 colunas no desktop)
- estrela no hover/focus para favoritar
- favoritos persistidos em `localStorage`
- busca case-insensitive

## Estrutura

- `/Users/isabellaherman/Documents/all/all/index.html`: pagina da rota `/all`
- `/Users/isabellaherman/Documents/all/all/styles.css`: estilo text-only inspirado no VibiWeb
- `/Users/isabellaherman/Documents/all/all/app.js`: login, busca, favoritos e renderizacao
- `/Users/isabellaherman/Documents/all/all/fonts/Minecraftia.ttf`: fonte usada no layout
- `/Users/isabellaherman/Documents/all/worker/src/index.js`: Cloudflare Worker (OAuth + API)
- `/Users/isabellaherman/Documents/all/worker/wrangler.toml`: config base do Worker

## Setup do Worker

1. Ajustar o dominio real no arquivo:
   - `/Users/isabellaherman/Documents/all/worker/wrangler.toml`
   - campo `REDIRECT_URI` para `https://SEU_WORKER_DOMAIN/auth/callback`

2. Criar OAuth App no GitHub:
   - Homepage URL: `https://studiovibi.github.io/all/`
   - Authorization callback URL: `https://SEU_WORKER_DOMAIN/auth/callback`

3. Definir secrets no Worker:

```bash
cd /Users/isabellaherman/Documents/all/worker
npm install
npx wrangler secret put CLIENT_ID
npx wrangler secret put CLIENT_SECRET
npx wrangler secret put COOKIE_SECRET
```

Para desenvolvimento local com `wrangler dev`, copie:
- `/Users/isabellaherman/Documents/all/worker/.dev.vars.example`
para `.dev.vars` no mesmo diretorio e preencha os valores.

4. Deploy:

```bash
npx wrangler deploy
```

## Setup do Frontend (`/all`)

1. Editar `window.STUDIOVIBI_LINKS_CONFIG.apiBase` em:
   - `/Users/isabellaherman/Documents/all/all/index.html`
2. Trocar `https://REPLACE_WITH_WORKER_DOMAIN` pelo dominio publicado do Worker.
3. Publicar a pasta `/all` no repositório `studiovibi.github.io`.

## Endpoints implementados

- `GET /auth/login`
- `GET /auth/callback`
- `POST /auth/logout`
- `GET /api/session`
- `GET /api/repos?org=StudioVibi`

`/api/repos` retorna:

- `name`
- `description`
- `html_url`
- `private`
- `archived`
- `updated_at`

e exclui repositorios arquivados.
