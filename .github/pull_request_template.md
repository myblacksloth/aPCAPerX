## Description

Briefly explain what changed and why.

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] Refactor
- [ ] Documentation
- [ ] Security hardening
- [ ] Build/CI/Docker

## Impacted areas

- [ ] FastAPI backend
- [ ] PCAP / Scapy analysis
- [ ] React frontend
- [ ] Packet filters
- [ ] External IP enrichment
- [ ] Security panel
- [ ] Documentation

## Verification performed

List the commands you ran and their result.

```bash
# examples
python -m py_compile backend/main.py backend/models.py backend/analyzer.py backend/external_enrichment.py
npm run build
docker-compose up --build
```

## Privacy and sensitive data

- [ ] I did not include real PCAP files or sensitive data in this commit.
- [ ] I did not add logs that expose payloads, credentials, or personal data.
- [ ] If this change sends data to external services, the behavior is opt-in and documented.

## Screenshots / UI notes

Attach screenshots or describe visual changes when relevant.

## Checklist

- [ ] Code is commented where the logic is not obvious.
- [ ] Documentation is updated when needed.
- [ ] Changes are limited to the PR scope.
- [ ] I checked that no temporary files or local artifacts are included.
