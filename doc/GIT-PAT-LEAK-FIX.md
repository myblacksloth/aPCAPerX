# Fix: Rimozione PAT da cronologia Git

## Problema

Un GitHub Personal Access Token (PAT) era stato accidentalmente usato come indirizzo email
dell'autore in 8 commit distribuiti su più branch. Questo esponeva il token nella cronologia
del repository, visibile a chiunque avesse accesso al repo o ai suoi oggetti Git.

I commit affetti erano quelli dei branch `feature/ai` e `feature/intl`, dove git era
configurato con il PAT come `user.email` invece dell'email corretta.

---

## Soluzione

### 1. Identificazione dei commit coinvolti

```bash
git log --all --format="%H %ae" | grep "ghp_"
```

Questo comando ha elencato tutti i commit (su tutti i branch e ref) il cui campo
`author.email` conteneva il token (`ghp_...`). Sono stati trovati 8 commit.

### 2. Riscrittura della cronologia con `git filter-branch`

```bash
git filter-branch --env-filter '
OLD_EMAIL="ghp_<token>"
NEW_EMAIL="25264956+myblacksloth@users.noreply.github.com"
NEW_NAME="myblacksloth"
if [ "$GIT_COMMITTER_EMAIL" = "$OLD_EMAIL" ]; then
    export GIT_COMMITTER_EMAIL="$NEW_EMAIL"
    export GIT_COMMITTER_NAME="$NEW_NAME"
fi
if [ "$GIT_AUTHOR_EMAIL" = "$OLD_EMAIL" ]; then
    export GIT_AUTHOR_EMAIL="$NEW_EMAIL"
    export GIT_AUTHOR_NAME="$NEW_NAME"
fi
' --tag-name-filter cat -f -- --all
```

`--env-filter` intercetta ogni commit e sostituisce le variabili d'ambiente usate da Git
per autore e committer. `--all` riscrive tutti i branch e i tag locali.

### 3. Pulizia dei backup e garbage collection

`git filter-branch` salva automaticamente i ref originali sotto `refs/original/`. Questi
vanno eliminati altrimenti gli oggetti con il token restano raggiungibili:

```bash
git for-each-ref --format="%(refname)" refs/original/ | while read ref; do
  git update-ref -d "$ref"
done

git reflog expire --expire=now --all
git gc --prune=now --aggressive
```

Dopo il `gc`, i vecchi oggetti (commit con PAT) sono stati rimossi definitivamente
dal repository locale.

### 4. Verifica

```bash
git log --all --format="%H %ae" | grep "ghp_"
```

Output vuoto: nessun commit con PAT rimasto nella cronologia.

### 5. Revoca del token

Il PAT esposto è stato revocato su GitHub:
**Settings → Developer settings → Personal access tokens → Revoke**

---

## Risultato

| Branch | Stato prima | Stato dopo |
|--------|-------------|------------|
| `feature/ai` | 8 commit con PAT come email | Pulito |
| `feature/intl` | Commit con PAT come email | Pulito |
| `main` / `develop` | Già puliti | Invariati |

La cronologia pubblica su GitHub era già priva dei commit con PAT (i branch erano
stati aggiornati in precedenza), quindi non è stato necessario un force push.

---

## Prevenzione futura

Configurare git correttamente prima di ogni nuovo repository:

```bash
git config --global user.email "25264956+myblacksloth@users.noreply.github.com"
git config --global user.name "myblacksloth"
```

Verificare la configurazione attiva in un repo con:

```bash
git config user.email
git config user.name
```

Non usare mai un PAT come valore di `user.email` o `user.name`.
