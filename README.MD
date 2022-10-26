## haproxy-protection

A fork and further development of a proof of concept from https://github.com/mora9715/haproxy_ddos_protector, a HAProxy configuration and lua scripts allowing a challenge-response page where users solve a captcha and/or proof-of-work. Intended to stop bots, spam, ddos.

Integrates with https://gitgud.io/fatchan/haproxy-panel-next to add/remove/edit domains, protection rules, blocked ips, backend server IPs, etc during runtime.

Improvements in this fork:

- Add a proof-of-work element, instead of only captcha.
- Supports hcaptcha or recaptcha.
- Support .onion/tor with the HAProxy PROXY protocol, using circuit identifiers as a substitute for IPs.
- Use HAProxy `http-request return` directive to directly serve challenge pages from the edge, with no separate backend.
- Fix multiple security issues that could result in bypassing the captcha.
- Add a bucket duration for cookie validity, so valid cookies don't last forever.
- Choose protection modes "none", "pow" or "pow+captcha" per-domain or per-domain+path, with paths taking priority.
- Provide a bash script that solves the proof-of-work and a form submission box for noscript users.
- Whitelist or blacklist IPs/subnets.
- Maintenance mode page for selected domains.
- Improved the appearance of the challenge page.
- Many bugfixes.

#### Environment variables

For docker, these are in docker-compose.yml. For production deployments, add them to `/etc/default/haproxy`.

NOTE: Use either HCAPTCHA_ or RECAPTHCA_, not both.
- HCAPTCHA_SITEKEY - your hcaptcha site key
- HCAPTCHA_SECRET - your hcaptcha secret key
- RECAPTCHA_SITEKEY - your recaptcha site key
- RECAPTCHA_SECRET - your recaptcha secret key
- CAPTCHA_COOKIE_SECRET - random string, a salt for captcha cookies
- POW_COOKIE_SECRET - different random string, a salt for pow cookies
- HMAC_COOKIE_SECRET - different random string, a salt for pow cookies
- RAY_ID - string to identify the HAProxy node by
- BUCKET_DURATION - how long between bucket changes, invalidating cookies
- CHALLENGE_INCLUDES_IP - any value, whether to lock solved challenges to IP or tor circuit
- BACKEND_NAME - Optional, name of backend to build from hosts.map
- SERVER_PREFIX - Optional, prefix of server names used in server-template
- POW_TIME - argon2 iterations
- POW_KB - argon2 memory usage in KB
- POW_DIFFICULTY - pow "difficulty" (you should use all 3 POW_ parameters to tune the difficulty)
- TOR_CONTROL_PORT_PASSWORD - the control port password for tor daemon

#### Run in docker (for testing/development)

Run docker compose:
```bash
docker compose up
```

Visit http://localhost

#### Installation

Requires HAProxy compiled with lua support, and version >=2.5 for the native lua httpclient support. For Debian and Ubuntu (and -based) distros, see https://haproxy.debian.net/ for packages.

- Clone the repo somewhere. `/var/www/haproxy-protection` works.
- Copy [haproxy.cfg](haproxy/haproxy.cfg) to `/etc/haproxy/haproxy.cfg`.
  - Please note this configuration is very minimal, and is simply an example configuration for haproxy-protection. You are expected to customise it significantly or otherwise copy the relevant parts into your own haproxy config.
- Copy (preferably link) [scripts](src/scripts) to `/etc/haproxy/scripts`.
- Copy (preferably link) [libs](src/libs) to `/etc/haproxy/libs`.
- Copy the map files from haproxy folder to `/etc/haproxy`.
- Install argon2, and the lua argon2 module with luarocks:
```bash
sudo apt install -y git lua5.3 liblua5.3-dev argon2 libargon2-dev luarocks
sudo git config --global url."https://".insteadOf git:// #don't ask.
sudo luarocks install argon2
```
- Test your haproxy config, `sudo haproxy -c -V -f /etc/haproxy/haproxy.cfg`. You should see "Configuration file is valid".

If you have problems, read the error messages before opening an issue that is simply a bad configuration.

### Tor

- Check the `bind` line comments. Switch to the one with `accept-proxy` and `option forwardfor`
- To generate a tor control port password:
```
$ tor --hash-password example
16:0175C41DDD88C5EA605582C858BC08FA29014215F233479A99FE78EDED
```
- Set `TOR_CONTROL_PORT_PASSWORD` env var to the same password (NOT the output hash)
- Add to your torrc (where xxxx is the output of `tor --hash-password`):
```
ControlPort 9051
HashedControlPassword xxxxxxxxxxxxxxxxx
```
- Don't forget to restart tor

#### Screenshots

![nocaptcha](img/nocaptcha.png "no captcha mode")
![captcha](img/captcha.png "captcha mode (pow done asynchronously in background)")
