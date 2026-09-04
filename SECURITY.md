# Security policy

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability and do not include credentials, tokens, private output, or personal data in a report.

Use GitHub's private vulnerability reporting flow:

1. Open the repository's **Security** tab.
2. Select **Advisories**.
3. Select **Report a vulnerability**.

Include the affected component and version, a minimal reproduction, expected impact, and any suggested mitigation. Remove real secrets and user data from the reproduction.

You should receive an initial acknowledgement within seven days. Please allow time for investigation and coordinated remediation before public disclosure.

## Supported versions

Only the latest release is supported with security updates.

## Service boundary

Flushout is designed to relay output without intentionally persisting stream content. Output still traverses Cloudflare infrastructure and exists in producer and browser memory. Do not stream credentials, private keys, regulated data, or production customer information.
