# Security

mojo-tls implements a security protocol, so a bug here can matter to every program that uses it. 0.1.1 has had an internal
audit (its findings are fixed or ruled out in the release note) but no independent one; the checks it does have are listed in the README.

## Report a vulnerability

Do not open a public issue. Use GitHub's private reporting: the **Report a vulnerability** button on the repository's
**Security** tab. Include the version, the smallest input or message sequence that shows it, and what you expected.

You will get a reply within 7 days. A fix ships as a patch release with an advisory that credits you, unless you ask not to be named.

## What counts

A handshake or record that an attacker can make us accept, decrypt wrongly, or leak a key or plaintext from; a certificate chain
accepted that should be refused; a crash, hang or unbounded memory use on peer input; a secret-dependent timing difference.

## Supported versions

Only the latest release gets fixes.
