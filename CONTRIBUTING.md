# Contributing to PCAPCaper

Thank you for your interest in the project. PCAPCaper analyzes network capture files, so contributions must handle PCAPs, IP addresses, payloads, and external services carefully.

## Recommended workflow

1. Open an issue or comment on an existing issue to align on goal and scope.
2. Create a dedicated branch:

```bash
git checkout -b feature/short-name
```

3. Keep the change focused.
4. Update the README or comments when you change user-facing behavior, APIs, or security behavior.
5. Open a pull request using the template.

## Local setup

Backend:

```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

Frontend:

```bash
cd frontend
npm install
npm run dev
```

Docker:

```bash
docker-compose up --build
```

## Checks before opening a PR

Run at least the applicable checks:

```bash
python -m py_compile backend/main.py backend/models.py backend/analyzer.py backend/external_enrichment.py
npm run build
docker-compose up --build
```

If you cannot run a command, state that in the PR.

## Code guidelines

- Write comments in English when adding non-obvious logic.
- Avoid unrelated refactors in the same PR.
- Do not introduce new dependencies when the existing stack is enough.
- For UI and UX, keep the style consistent with Tailwind and the existing components.
- For the backend, keep endpoints explicit and documented.

## Privacy and sensitive data

- Do not commit real PCAP files.
- Do not commit payloads, credentials, tokens, cookies, or personal data.
- Anonymize IP addresses and hostnames in examples when needed.
- Features that send data to external services must be opt-in, visible to the user, and documented.
- Private, local, and reserved IP addresses must not be sent to external services.

## Issues

Use the templates in `.github/ISSUE_TEMPLATE`:

- bug report for malfunctions;
- feature request for new features;
- security report for risks or vulnerabilities.

## Pull requests

A PR should include:

- change description;
- motivation;
- tests/checks performed;
- screenshots if the UI changed;
- privacy notes if PCAPs, IP addresses, or external services are involved.

## License

By contributing, you agree that your contribution is distributed under the project license.
