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
- TOR_CONTROL_PORT_PASSWORD - the control port password for tor daemon
- RAY_ID - string to identify the HAProxy node by
- BACKEND_NAME - Optional, name of backend to build from hosts.map
- SERVER_PREFIX - Optional, prefix of server names used in server-template
- VERIFY_BACKEND_SSL - whether to verify backend ssl, requires you have a private CA, install the cert on the proxies, and CA signed certs on your origins.
- CHALLENGE_EXPIRY - how long solution cookies last for, in seconds
- CHALLENGE_INCLUDES_IP - any value, whether to lock solved challenges to IP or tor circuit
- ARGON_TIME - default argon2 iterations
- ARGON_KB - default argon2 memory usage in KB
- POW_DIFFICULTY - default pow difficulty
- POW_TYPE - type of ahsh algorithm for pow "argon2" or "sha256"

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
- Copy/link [scripts](src/lua/scripts) to `/etc/haproxy/scripts`.
- Copy/link [libs](src/lua/libs) to `/etc/haproxy/libs`.
- Copy/link [template](haproxy/template) to `/etc/haproxy/template`.
- Copy/link [js](src/js) to `/etc/haproxy/js`.
- Copy [map](haproxy/map) to `/etc/haproxy/map`.
- Install argon2, and the lua argon2 module with luarocks:
```bash
sudo apt install -y git lua5.3 liblua5.3-dev argon2 libargon2-dev luarocks
sudo git config --global url."https://".insteadOf git:// #don't ask.
sudo luarocks install argon2
```
- Test your haproxy config, `sudo haproxy -c -V -f /etc/haproxy/haproxy.cfg`. You should see "Configuration file is valid".

NOTE: the provided configuration is only an example. You are expected to customise it significantly or otherwise copy the relevant parts into your own haproxy config.

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
