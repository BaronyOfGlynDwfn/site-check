# Webminister Site Check

A public page where webministers paste their WordPress **Site Health** info and get:

- **Fix now**: plugins, themes or WordPress itself with a known security problem and an available fix
- **Turn off: no fix yet**: known problems the maker hasn't fixed
- **Remove**: inactive items that are outdated or vulnerable
- **Ask your host**: PHP problems, with a ready-to-send message
- **Update when you can** and **Couldn't check**

Plus a **bulletin list**: plain-language entries for problems that matter to An Tir sites, each with how to check, how to fix, and when to ask for help.

Published at https://baronyofglyndwfn.github.io/site-check/ once GitHub Pages is enabled.

## How it works

Everything runs in the visitor's browser (`site/`, plain HTML/CSS/JS, no build step).

1. `site/lib.js` parses the "Copy site info to clipboard" text from Tools → Site Health → Info.
2. Each plugin/theme name is matched to its wordpress.org listing (`api.wordpress.org`). Exact name matches are accepted; looser matches (prefix, folder-style slug, same author) are accepted only when Site Health's "latest version" (which comes from wordpress.org) equals the listing's version. Anything else is reported as "Couldn't check" rather than guessed.
3. Known vulnerabilities come from [WPVulnerability](https://www.wpvulnerability.com/) (CC0 public domain, no API key, CORS-enabled), filtered to the installed version.
4. Records the aggregator marks "unfixed" are dropped when every cited source states a maximum affected version below the installed one (seen with Content Control: aggregator said "<= 2.7.4 unfixed", both sources said "<= 2.6.5").

Only names and version numbers leave the browser. Paths, user counts and settings in the paste are never sent.

Known limits: WordPress sites only; server software other than PHP isn't checked (hosts patch distro packages without changing version numbers, so version matching gives false alarms); WPVulnerability's `closed` flag and `latest` field are ignored (unreliable / a timestamp).

## Adding a bulletin

Add an entry to `site/bulletins.json` (newest anywhere; the page sorts by date). Fields: `id`, `date` (YYYY-MM-DD), `severity` (critical/high/medium/low), `title`, `summary`, `affects` (`[{kind: plugin|theme|core|php, slug?, fixedIn}]`, which links checker results to the bulletin), `check` and `fix` (arrays of steps with exact wp-admin clicks), `help`, `technical`, `sources` (https URLs). `test/bulletins.test.mjs` validates the file, in CI and before every Pages deploy.

Write for a volunteer with admin access and no security background: what it is, who is affected, exact clicks, when to ask the kingdom webministry.

## Tests

    node --test test/*.test.mjs

`test/fixtures/site-health-sample.txt` is a synthetic Site Health export. Tests use a fake network; nothing calls the real services.

## Credits and disclosure

Vulnerability data: WPVulnerability (CC0). Version data: WordPress.org. Built with help from Claude (Anthropic), per Corpora's AI disclosure requirement. Not an official publication of the SCA or the Kingdom of An Tir.
