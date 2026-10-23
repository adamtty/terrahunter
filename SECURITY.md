# Security policy

## Reporting a vulnerability

Please report security issues **privately** through GitHub:
[**Report a vulnerability**](https://github.com/adamtty/terrahunter/security/advisories/new).
Don't open a public issue for them.

Include what you found, how to reproduce it (a small Terraform directory is ideal), and what an attacker
could do with it. You'll get a reply within a week. Once it's fixed, you'll be credited in the advisory
unless you'd rather not be.

## Supported versions

terrahunter is being rebuilt. Only the latest commit on `main` is supported; there are no release branches.

## Scope

terrahunter is built to run on Terraform you don't trust, such as a pull request from a stranger. So the
most interesting reports are ones where the code under review can:

- run commands, read files or reach the network on the machine or CI runner running terrahunter
- get secrets (hardcoded credentials it finds, your API keys, files outside the scanned folder) into a report,
  a diagram or anywhere else they shouldn't go
- make terrahunter show an attack path as proven when a hop isn't, or hide a real one
- crash or hang a scan, or make it exit 0 when it should have failed
- inject markup, scripts, links or terminal escape sequences into the reports, the diagram or the terminal

Out of scope: vulnerabilities in trivy or checkov themselves (report those upstream), and findings that need an
attacker who can already change terrahunter's own install or your environment variables.
