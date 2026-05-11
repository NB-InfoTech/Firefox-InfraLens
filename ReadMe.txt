Title: InfraLens - Security & Infra Page Inspector

Description
InfraLens is a read-only Firefox extension for quick infrastructure and security checks on the current webpage.

Current features
- HTTPS / HTTP protocol status
- Page-level security headers
  - Strict-Transport-Security
  - Content-Security-Policy
  - X-Frame-Options
  - X-Content-Type-Options
  - Referrer-Policy
  - Permissions-Policy
  - COOP / COEP / CORP capture in exported JSON
- Basic CSP weakness detection
  - unsafe-inline
  - unsafe-eval
  - wildcard source
  - missing default-src
- Mixed content detection
  - active mixed content
  - passive mixed content
- Main-frame redirect chain
- Set-Cookie security summary when exposed by the browser
  - Secure
  - HttpOnly
  - SameSite
- Page response time measured by webRequest timestamps
- Fresh active header scan when the popup opens, merged with passive browser observations
- Firefox DNS lookup for current page IP address using browser.dns
- Best-effort CDN detection from response headers and DNS canonical name
- Best-effort CMS detection from response headers and HTML markers
- Best-effort language/runtime detection from headers and HTML markers
- TLS certificate issuer display using Firefox webRequest security info
- Best-effort web application version, theme, content directory, and ads/analytics detection
- Overall score and grade
- Copy curl command
- Reload current tab
- Hard reload current tab with cache bypass
- Export TXT / JSON report
- Open current site in SecurityHeaders, SSL Labs, and VirusTotal
- Open current site in Sucuri SiteCheck to review malware and blocklist status
- Dedicated Blocklist Check section in the popup with a Sucuri SiteCheck button
- TXT reports include an External Checks section with Sucuri, SecurityHeaders, SSL Labs, and VirusTotal links
- Popup header shows icon16.png beside the InfraLens name
- Popup header shows the extension version from manifest.json
- Settings gear opens an internal extension reference page
- Internal settings page explains HTTPS, HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, cookie flags, mixed content, redirects, Sucuri, and VirusTotal
- Settings page includes enable / disable controls for popup sections and action buttons
- User feature preferences are saved with extension storage sync
- Popup and settings page include Copyright @NB InfoTech 2026

Privacy posture
- Read-only
- No tracking
- No ads
- No page modification
- No backend required
- Settings are stored only as extension preferences using browser extension storage

Free tier recommendation
- Current-tab scan
- HTTPS / HTTP status
- Basic security headers
- Basic CSP checks
- Mixed content warning
- Redirect chain
- Basic cookie security summary
- Security score
- TXT / JSON export
- External scan links
  - SecurityHeaders
  - SSL Labs
  - VirusTotal
  - Sucuri SiteCheck
- Copy curl command

Paid tier recommendation
- Audit history per domain
- Compare current scan with previous scan
- PDF / CSV professional reports
- Company branding in exports
- Custom security policies
- Multi-page crawling
- Scheduled monitoring
- Certificate expiry alerts
- Team sharing
- Compliance mapping
- Jira / Slack / Teams integrations

Firefox Add-ons preparation
1. Keep manifest.json at the ZIP root.
2. Use Manifest V3 with Firefox background scripts.
3. Include icon16.png, icon48.png, and icon128.png.
4. Add screenshots that show the popup and report output.
5. Publish a clear privacy policy.
6. Explain why webRequest and all_urls are needed:
   InfraLens reads response headers and request metadata for the current page to inspect security posture.
7. Submit the ZIP through addons.mozilla.org for signing before public distribution.

Monetization note
Use your own licensing/payment flow if you add Pro features later.

Change history
- 2026-05-10: Created Firefox-compatible extension folder with Manifest V3 Firefox background scripts, Gecko metadata, and Firefox Add-ons preparation notes.
- 2026-05-10: Added popup version display, Infrastructure section, Firefox DNS-based IP lookup, best-effort CDN detection, best-effort CMS detection, and README change history tracking.
- 2026-05-10: Moved SecurityHeaders, SSL Labs, VirusTotal, and Sucuri SiteCheck buttons under Blocklist Check, leaving Quick Tools focused on copy, reload, and export actions.
- 2026-05-10: Expanded Site Details with language/runtime, TLS certificate issuer, web application version, theme, content directory, and ads/analytics detection; added webRequestBlocking permission for Firefox TLS security info.
- 2026-05-10: Added NB InfoTech branding, YouTube channel link, and review/rating request to the settings page.
