# PR Checker CI Action

[![Python|main](../../actions/workflows/python.yml/badge.svg?branch=main)](../../actions/workflows/python.yml?branch=main)

A PR checker CI Action for SUSE Security Team work. This is mainly useful for Proactive Team whitelisting submissions, but can be generally useful.

It runs on all commits found in a PR, and performs the following checks:
- Detect similar bug references (bsc#123456): typos, dropped digits, off-by-one, ...
- Detect references to nonexisting or non-publig bugs on Bugzilla
- Detect bug reference removals
- Detect wrong-length SHA-256 hashes (e.g. copy/paste errors)