# Security

samlscope processes untrusted input by design. Please report vulnerabilities privately through the repository's security advisory feature, not in public issues.

In scope: parser escapes (XXE, entity expansion, decompression bombs), signature verification errors (accepting an invalid signature, or misreporting what was signed), rendering of untrusted content as rich text in the desktop app, and any network access by the app.

Never attach real SAML messages from production systems to a report. Reproduce with generated test data instead.
