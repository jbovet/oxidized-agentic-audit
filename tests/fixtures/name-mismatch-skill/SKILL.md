---
name: wrong-name
description: A skill whose name does not match its directory. Use when testing the name-directory-mismatch rule.
allowed-tools:
  - Bash(find)
---

# Name Mismatch Skill

This fixture exists to verify that `frontmatter/name-directory-mismatch` fires when
the `name` field in frontmatter differs from the containing directory name.
