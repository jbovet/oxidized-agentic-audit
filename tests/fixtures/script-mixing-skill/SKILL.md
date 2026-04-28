---
name: script-mixing-skill
description: A skill with a Cyrillic а instead of a
compatibility: "Python 3.8+"
---

# Test Skill

This skill demonstrates script-mixing vulnerabilities.

## Examples

This example uses a Greek ο (homoglyph) in a variable name: `print('Hellο World')`

Here's some text with a Greek ο that looks like o but isn't: Pythοn

This line has a bidirectional override mark that may not be visible: Text‮with‮override
