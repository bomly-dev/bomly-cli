# ADR-0003: YAML configuration is nested at the file boundary

- **Date:** 2026-05-30
- **Status:** Accepted

Bomly's YAML files use strict nested groups such as `target`, `analysis`, `policy`, `network.proxy`, and `matchers.osv`, while `config.Resolved` remains flat. Nesting keeps customer-authored files readable without spreading YAML organization through the CLI and engine. Each YAML leaf maps back to one flat runtime field, and layered files preserve explicit zero values, including empty lists. Unknown keys and the former flat YAML keys fail with migration guidance so typos cannot silently disable requested behavior.
