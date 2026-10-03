# Security Policy

## Scope
DRAGNET is a defensive analysis tool. It never executes, downloads or stores malware. Malware evidence is a JSON
feature record (hashes, imphash, code-reuse fingerprints). All bundled fixtures are synthetic: reserved IP ranges,
`.example` domains, fabricated hashes and simulated actor labels.

## Reporting a vulnerability
Please report vulnerabilities privately through GitHub's private vulnerability reporting:
<https://github.com/rakshit-737/dragnet/security/advisories/new> ("Report a vulnerability" on the Security tab).
Do not open a public issue. Include reproduction steps, and expect an acknowledgement within 7 days.

The repository has Dependabot alerts and security updates, secret scanning and push protection enabled.

## Safe use
- Do not add real samples or real victim data to this repository.
- Treat outputs as analytic judgments that need human review, not as proof. See [Safety and ethics](https://github.com/rakshit-737/dragnet#safety-and-ethics).
