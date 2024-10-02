## haproxy-protection

HAProxy configuration and lua scripts allowing a challenge-response page where users solve a captcha and/or proof-of-work. Intended to stop bots, spam, ddos.

Integrates with https://gitgud.io/fatchan/haproxy-panel-next to add/remove/edit domains, protection rules, blocked ips, backend server IPs, etc during runtime.

Originally inspired by a proof of concept from https://github.com/mora9715/haproxy_ddos_protector.

#### Features / improvements in this fork:

- Implement a proof-of-work mode, in addition to the existing captcha only mode.
- Ability to choose between argon2 or sha256 proof of work modes.
- Sharing POW answers with storage events to prevent unnecessary re-solving when opening multiple tabs.
- Supports either hcaptcha or recaptcha.
- Support .onion/tor with the HAProxy PROXY protocol, using circuit identifiers as a substitute for IPs.
- Allow users without javascript to solve the POW by providing a shell script and html form inside `noscript` tags.
- Use HAProxy `http-request return` directive to directly serve files from the edge without a separate backend.
- Adjustable cookie validity lifetime.
- Adjustable "mode" ("none", "pow" or "pow+captcha") per domain or domain+path
- Improved the appearance of the challenge page.
- Add several useful maps & acls to the haproxy config:
  - Whitelist or blacklist IPs/subnets.
  - Rerwite/redirect specific paths or whole domains.
  - Maintenance mode page for selected domains.
- Geoip mapping support for alt-svc headers.
- Support simple load balancing to multiple backends per domain dynamically.
- Multiple language support with locales files (currently en-US and pt-PT).
- Fix multiple security issues.
- Many bugfixes.

#### Installation

See [INSTALLATION.md](INSTALLATION.md)

## For generous people

Bitcoin (BTC): [`bc1q4elrlz5puak4m9xy3hfvmpempnpqpu95v8s9m6`](bitcoin:bc1q4elrlz5puak4m9xy3hfvmpempnpqpu95v8s9m6)

Monero (XMR): [`89J9DXPLUBr5HjNDNZTEo4WYMFTouSsGjUjBnUCCUxJGUirthnii4naZ8JafdnmhPe4NP1nkWsgcK82Uga7X515nNR1isuh`](monero:89J9DXPLUBr5HjNDNZTEo4WYMFTouSsGjUjBnUCCUxJGUirthnii4naZ8JafdnmhPe4NP1nkWsgcK82Uga7X515nNR1isuh)
