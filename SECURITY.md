# Security

Huginn sits next to a machine that is attacked on purpose, so security problems in Huginn matter.

## Reporting a problem

Please **do not open a public issue**. Report it privately through
[GitHub's private vulnerability reporting](https://github.com/ancientswede/Huginn/security/advisories/new).
Include the Huginn version, what an attacker could do and how to reproduce it.

You will get an answer within a week. Fixes are released as a new version, and the changelog says
what was fixed once an update is available.

## What counts

- Anything that lets an attacker on the honeypot reach Huginn, your LAN or other machines
  (for example through `hp-export`, the forced SSH command or the data it returns)
- Attacker-controlled data (commands, passwords, URLs, file names) that runs as code in the web page,
  in a spreadsheet export or in a blocklist feed
- Getting past the login, the CSRF protection or the feed token
- The install and update scripts doing something unsafe

## Not a Huginn problem

- Weaknesses in Cowrie, OpenCanary or endlessh themselves: please report those to their projects
- A honeypot that can reach your LAN because it was not isolated (see "Read this before you open any ports" in the README)
