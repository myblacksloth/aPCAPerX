---
name: Security report
about: Report a potential security issue
title: "[Security]: "
labels: ["security"]
assignees: []
---

## Note

If the issue may allow unauthorized access, data exfiltration, code execution, or exposure of sensitive PCAP data, avoid publicly exploitable details. Open a minimal issue and request a private contact channel.

## Summary

Describe the issue at a high level.

## Potential impact

- [ ] Data exposure
- [ ] Code execution
- [ ] SSRF / unexpected external calls
- [ ] Upload control bypass
- [ ] XSS / frontend issue
- [ ] Other

## Involved components

- [ ] FastAPI backend
- [ ] PCAP / Scapy analysis
- [ ] React frontend
- [ ] External IP enrichment
- [ ] Docker / Nginx

## Controlled reproduction

Provide minimal steps without including sensitive data.

## Suggested mitigation

If you already have a proposed fix, describe it.
