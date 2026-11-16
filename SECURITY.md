# Security Policy

## Project status

AIVO AgentGuard is under active research and is not production-ready. Do not rely on it to secure production systems, custody assets, authorize live transactions, or protect private keys.

## Reporting a vulnerability

Do not disclose exploitable vulnerabilities in public issues. Until a dedicated security contact is published, contact the repository owner privately through GitHub's repository security advisory feature.

Include the affected commit or release, impact, reproduction steps, and any suggested mitigation. Avoid including real credentials, private keys, seed phrases, or personal data.

## Response expectations

The maintainers will acknowledge reports as soon as reasonably practicable, assess severity and affected versions, coordinate remediation, and publish an advisory when disclosure is safe. No response-time SLA is currently promised.

## Security boundaries

The project does not request or store user private keys or seed phrases. Integrations must preserve credential isolation and must not treat an AgentGuard decision as proof that an external execution succeeded.
