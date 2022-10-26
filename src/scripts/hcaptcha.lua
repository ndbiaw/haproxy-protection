_M = {}

local url = require("url")
local utils = require("utils")
local cookie = require("cookie")
local json = require("json")
local sha = require("sha")
local randbytes = require("randbytes")
local argon2 = require("argon2")
local pow_difficulty = tonumber(os.getenv("POW_DIFFICULTY") or 18)
local pow_kb = tonumber(os.getenv("POW_KB") or 6000)
local pow_time = tonumber(os.getenv("POW_TIME") or 1)
argon2.t_cost(pow_time)
argon2.m_cost(pow_kb)
argon2.parallelism(1)
argon2.hash_len(32)
argon2.variant(argon2.variants.argon2_id)

-- Testing only
-- require("socket")
-- require("print_r")

local captcha_secret = os.getenv("HCAPTCHA_SECRET") or os.getenv("RECAPTCHA_SECRET")
local captcha_sitekey = os.getenv("HCAPTCHA_SITEKEY") or os.getenv("RECAPTCHA_SITEKEY")
local captcha_cookie_secret = os.getenv("CAPTCHA_COOKIE_SECRET")
local pow_cookie_secret = os.getenv("POW_COOKIE_SECRET")
local hmac_cookie_secret = os.getenv("HMAC_COOKIE_SECRET")
local ray_id = os.getenv("RAY_ID")

local captcha_map = Map.new("/etc/haproxy/ddos.map", Map._str);
local captcha_provider_domain = ""
local captcha_classname = ""
local captcha_script_src = ""
local captcha_siteverify_path = ""
local captcha_backend_name = ""
if os.getenv("HCAPTCHA_SITEKEY") then
	captcha_provider_domain = "hcaptcha.com"
	captcha_classname = "h-captcha"
	captcha_script_src = "https://hcaptcha.com/1/api.js"
	captcha_siteverify_path = "/siteverify"
	captcha_backend_name = "hcaptcha"
else
	captcha_provider_domain = "www.google.com"
	captcha_classname = "g-recaptcha"
	captcha_script_src = "https://www.google.com/recaptcha/api.js"
	captcha_siteverify_path = "/recaptcha/api/siteverify"
	captcha_backend_name = "recaptcha"
end

function _M.setup_servers()
	if pow_difficulty < 8 then
		error("POW_DIFFICULTY must be > 8. Around 16-32 is better")
	end
	local backend_name = os.getenv("BACKEND_NAME")
	local server_prefix = os.getenv("SERVER_PREFIX")
	if backend_name == nil or server_prefix == nil then
		return;
	end
	local hosts_map = Map.new("/etc/haproxy/hosts.map", Map._str);
	local handle = io.open("/etc/haproxy/hosts.map", "r")
	local line = handle:read("*line")
	local counter = 1
	while line do
		local domain, backend_host = line:match("([^%s]+)%s+([^%s]+)")
		local port_index = backend_host:match'^.*():'
		local backend_hostname = backend_host:sub(0, port_index-1)
		local backend_port = backend_host:sub(port_index + 1)
		core.set_map("/etc/haproxy/backends.map", domain, server_prefix..counter)
		local proxy = core.proxies[backend_name].servers[server_prefix..counter]
		proxy:set_addr(backend_hostname, backend_port)
		proxy:set_ready()
		line = handle:read("*line")
		counter = counter + 1
	end
	handle:close()
end

-- main page template
local body_template = [[
<!DOCTYPE html>
<html>
	<head>
		<meta name='viewport' content='width=device-width initial-scale=1'>
		<title>Hold on...</title>
		<style>
			:root{--text-color:#c5c8c6;--bg-color:#1d1f21}
			@media (prefers-color-scheme:light){:root{--text-color:#333;--bg-color:#EEE}}
			.h-captcha,.g-recaptcha{min-height:85px;display:block}
			.red{color:red;font-weight:bold}
			.powstatus{color:green;font-weight:bold}
			a,a:visited{color:var(--text-color)}
			body,html{height:100%%}
			body{display:flex;flex-direction:column;background-color:var(--bg-color);color:var(--text-color);font-family:Helvetica,Arial,sans-serif;max-width:1200px;margin:0 auto;padding: 0 20px}
			details{transition: border-left-color 0.5s;max-width:1200px;text-align:left;border-left: 2px solid var(--text-color);padding:10px}
			code{background-color:#dfdfdf30;border-radius:3px;padding:0 3px;}
			img,h3,p{margin:0 0 5px 0}
			footer{font-size:x-small;margin-top:auto;margin-bottom:20px;text-align:center}
			img{display:inline}
			.pt{padding-top:15vh;display:flex;align-items:center;word-break:break-all}
			.pt img{margin-right:10px}
			details[open]{border-left-color: #1400ff}
			.lds-ring{display:inline-block;position:relative;width:80px;height:80px}.lds-ring div{box-sizing:border-box;display:block;position:absolute;width:32px;height:32px;margin:10px;border:5px solid var(--text-color);border-radius:50%%;animation:lds-ring 1.2s cubic-bezier(0.5, 0, 0.5, 1) infinite;border-color:var(--text-color) transparent transparent transparent}.lds-ring div:nth-child(1){animation-delay:-0.45s}.lds-ring div:nth-child(2){animation-delay:-0.3s}.lds-ring div:nth-child(3){animation-delay:-0.15s}@keyframes lds-ring{0%%{transform:rotate(0deg)}100%%{transform:rotate(360deg)}}
		</style>
		<noscript>
			<style>.jsonly{display:none}</style>
		</noscript>
		<script src="/js/argon2.js"></script>
		<script src="/js/challenge.js"></script>
	</head>
	<body data-pow="%s" data-diff="%s" data-time="%s" data-kb="%s">
		%s
		%s
		%s
		<noscript>
			<br>
			<p class="red">JavaScript is required on this page.</p>
			%s
		</noscript>
		<div class="powstatus"></div>
		<footer>
			<p>Security and Performance by <a href="https://gitgud.io/fatchan/haproxy-protection/">haproxy-protection</a></p>
			<p>Node: <code>%s</code></p>
		</footer>
	</body>
</html>
]]

local noscript_extra_template = [[
			<details>
				<summary>No JavaScript?</summary>
				<ol>
					<li>
						<p>Run this in a linux terminal (requires <code>argon2</code> package installed):</p>
						<code style="word-break: break-all;">
							echo "Q0g9IiQyIjtCPSQocHJpbnRmICcwJS4wcycgJChzZXEgMSAkNCkpO2VjaG8gIldvcmtpbmcuLi4iO0k9MDt3aGlsZSB0cnVlOyBkbyBIPSQoZWNobyAtbiAkQ0gkSSB8IGFyZ29uMiAkMSAtaWQgLXQgJDUgLWsgJDYgLXAgMSAtbCAzMiAtcik7RT0ke0g6MDokNH07W1sgJEUgPT0gJEIgXV0gJiYgZWNobyAiT3V0cHV0OiIgJiYgZWNobyAkMSMkMiMkMyMkSSAmJiBleGl0IDA7KChJKyspKTtkb25lOwo=" | base64 -d | bash -s %s %s %s %s %s %s
						</code>
					<li>Paste the script output into the box and submit:
					<form method="post">
						<textarea name="pow_response" placeholder="script output" required></textarea>
						<div><input type="submit" value="submit" /></div>
					</form>
				</ol>
			</details>
]]

-- title with favicon and hostname
local site_name_section_template = [[
		<h3 class="pt">
			<img src="/favicon.ico" width="32" height="32" alt="icon">
			%s
		</h3>
]]

-- spinner animation for proof of work
local pow_section_template = [[
		<h3>
			Checking your browser for robots 🤖
		</h3>
		<div class="jsonly">
			<div class="lds-ring"><div></div><div></div><div></div><div></div></div>
		</div>
]]

-- message, captcha form and submit button
local captcha_section_template = [[
		<h3>
			Please solve the captcha to continue.
		</h3>
		<div id="captcha" class="jsonly">
			<div class="%s" data-sitekey="%s" data-callback="onCaptchaSubmit"></div>
			<script src="%s" async defer></script>
		</div>
]]

-- kill a tor circuit
function _M.kill_tor_circuit(txn)
	local ip = txn.sf:src()
	if ip:sub(1,19) ~= "fc00:dead:beef:4dad" then
		return -- not a tor circuit id/ip. we shouldn't get here, but just in case.
	end
	-- split the IP, take the last 2 sections
	local split_ip = utils.split(ip, ":")
	local aa_bb = split_ip[5] or "0000"
	local cc_dd = split_ip[6] or "0000"
	aa_bb = string.rep("0", 4 - #aa_bb) .. aa_bb
	cc_dd = string.rep("0", 4 - #cc_dd) .. cc_dd
	-- convert the last 2 sections to a number from hex, which makes the circuit ID
	local circuit_identifier = tonumber(aa_bb..cc_dd, 16)
	print('Closing Tor circuit ID: '..circuit_identifier..', "IP": '..ip)
	utils.send_tor_control_port(circuit_identifier)
end

function _M.view(applet)

	-- set response body and declare status code
	local response_body = ""
	local response_status_code

	-- if request is GET, serve the challenge page
	if applet.method == "GET" then

		-- get the user_key#challenge#sig
		local user_key = sha.bin_to_hex(randbytes(16))
		local challenge_hash = utils.generate_secret(applet, pow_cookie_secret, user_key, true)
		local signature = sha.hmac(sha.sha3_256, hmac_cookie_secret, user_key .. challenge_hash)
		local combined_challenge = user_key .. "#" .. challenge_hash .. "#" .. signature

		-- define body sections
		local site_name_body = ""
		local captcha_body = ""
		local pow_body = ""
		local noscript_extra_body = ""

		-- check if captcha is enabled, path+domain priority, then just domain, and 0 otherwise
		local captcha_enabled = false
		local host = applet.headers['host'][0]
		local path = applet.qs; --because on /bot-check?/whatever, .qs (query string) holds the "path"

		local captcha_map_lookup = captcha_map:lookup(host..path) or captcha_map:lookup(host) or 0
		captcha_map_lookup = tonumber(captcha_map_lookup)
		if captcha_map_lookup == 2 then
			captcha_enabled = true
		end

		-- pow at least is always enabled when reaching bot-check page
		site_name_body = string.format(site_name_section_template, host)
		if captcha_enabled then
			captcha_body = string.format(captcha_section_template, captcha_classname,
				captcha_sitekey, captcha_script_src)
		else
			pow_body = pow_section_template
			noscript_extra_body = string.format(noscript_extra_template, user_key, challenge_hash, signature,
				math.ceil(pow_difficulty/8), pow_time, pow_kb)
		end

		-- sub in the body sections
		response_body = string.format(body_template, combined_challenge,
			pow_difficulty, pow_time, pow_kb,
			site_name_body, pow_body, captcha_body, noscript_extra_body, ray_id)
		response_status_code = 403

	-- if request is POST, check the answer to the pow/cookie
	elseif applet.method == "POST" then

		-- if they fail, set a var for use in ACLs later
		local valid_submission = false

		-- parsed POST body
		local parsed_body = url.parseQuery(applet.receive(applet))

		-- whether to set cookies sent as secure or not
		local secure_cookie_flag = " Secure=true;"
		if applet.sf:ssl_fc() == "0" then
			secure_cookie_flag = ""
		end

		-- handle setting the POW cookie
		local user_pow_response = parsed_body["pow_response"]
		if user_pow_response then

			-- split the response up (makes the nojs submission easier because it can be a single field)
			local split_response = utils.split(user_pow_response, "#")

			if #split_response == 4 then
				local given_user_key = split_response[1]
				local given_challenge_hash = split_response[2]
				local given_signature = split_response[3]
				local given_answer = split_response[4]

				-- regenerate the challenge and compare it
				local generated_challenge_hash = utils.generate_secret(applet, pow_cookie_secret, given_user_key, true)
				if given_challenge_hash == generated_challenge_hash then

					-- regenerate the signature and compare it
					local generated_signature = sha.hmac(sha.sha3_256, hmac_cookie_secret, given_user_key .. given_challenge_hash)
					if given_signature == generated_signature then

						-- do the work with their given answer
						local full_hash = argon2.hash_encoded(given_challenge_hash .. given_answer, given_user_key)

						-- check the output is correct
						local hash_output = utils.split(full_hash, '$')[6]:sub(0, 43) -- https://github.com/thibaultcha/lua-argon2/issues/37
						local hex_hash_output = sha.bin_to_hex(sha.base64_to_bin(hash_output));
						if utils.checkdiff(hex_hash_output, pow_difficulty) then

							-- the answer was good, give them a cookie
							local signature = sha.hmac(sha.sha3_256, hmac_cookie_secret, given_user_key .. given_challenge_hash .. given_answer)
							local combined_cookie = given_user_key .. "#" .. given_challenge_hash .. "#" .. given_answer .. "#" .. signature
							applet:add_header(
								"set-cookie",
								string.format(
									"z_ddos_pow=%s; Expires=Thu, 31-Dec-37 23:55:55 GMT; Path=/; Domain=.%s; SameSite=Strict;%s",
									combined_cookie,
									applet.headers['host'][0],
									secure_cookie_flag
								)
							)
							valid_submission = true

						end
					end
				end
			end
		end

		-- handle setting the captcha cookie
		local user_captcha_response = parsed_body["h-captcha-response"] or parsed_body["g-recaptcha-response"]
		if valid_submission and user_captcha_response then -- only check captcha if POW is already correct
			-- format the url for verifying the captcha response
			local captcha_url = string.format(
				"https://%s%s",
				core.backends[captcha_backend_name].servers[captcha_backend_name]:get_addr(),
				captcha_siteverify_path
			)
			-- construct the captcha body to send to the captcha url
			local captcha_body = url.buildQuery({
				secret=captcha_secret,
				response=user_captcha_response
			})
			-- instantiate an http client and make the request
			local httpclient = core.httpclient()
			local res = httpclient:post{
				url=captcha_url,
				body=captcha_body,
				headers={
					[ "host" ] = { captcha_provider_domain },
					[ "content-type" ] = { "application/x-www-form-urlencoded" }
				}
			}
			-- try parsing the response as json
			local status, api_response = pcall(json.decode, res.body)
			if not status then
				api_response = {}
			end
			-- the response was good i.e the captcha provider says they passed, give them a cookie
			if api_response.success == true then

				local user_key = sha.bin_to_hex(randbytes(16))
				local user_hash = utils.generate_secret(applet, captcha_cookie_secret, user_key, true)
				local signature = sha.hmac(sha.sha3_256, hmac_cookie_secret, user_key .. user_hash)
				local combined_cookie = user_key .. "#" .. user_hash .. "#" .. signature
				applet:add_header(
					"set-cookie",
					string.format(
						"z_ddos_captcha=%s; Expires=Thu, 31-Dec-37 23:55:55 GMT; Path=/; Domain=.%s; SameSite=Strict;%s",
						combined_cookie,
						applet.headers['host'][0],
						secure_cookie_flag
					)
				)
				valid_submission = valid_submission and true

			end
		end

		if not valid_submission then
			_M.kill_tor_circuit(applet)
		end

		-- redirect them to their desired page in applet.qs (query string)
		-- if they didn't get the appropriate cookies they will be sent back to the challenge page
		response_status_code = 302
		applet:add_header("location", applet.qs)

	-- else if its another http method, just 403 them
	else
		response_status_code = 403
	end

	-- finish sending the response
	applet:set_status(response_status_code)
	applet:add_header("content-type", "text/html; charset=utf-8")
	applet:add_header("content-length", string.len(response_body))
	applet:start_response()
	applet:send(response_body)

end

-- check if captcha is enabled, path+domain priority, then just domain, and 0 otherwise
function _M.decide_checks_necessary(txn)
	local host = txn.sf:hdr("Host")
	local path = txn.sf:path();
	local captcha_map_lookup = captcha_map:lookup(host..path) or captcha_map:lookup(host) or 0
	captcha_map_lookup = tonumber(captcha_map_lookup)
	if captcha_map_lookup == 1 then
		txn:set_var("txn.validate_pow", true)
	elseif captcha_map_lookup == 2 then
		txn:set_var("txn.validate_captcha", true)
		txn:set_var("txn.validate_pow", true)
	end
	-- otherwise, domain+path was set to 0 (whitelist) or there is no entry in the map
end

-- check if captcha cookie is valid, separate secret from POW
function _M.check_captcha_status(txn)
	local parsed_request_cookies = cookie.get_cookie_table(txn.sf:hdr("Cookie"))
	local received_captcha_cookie = parsed_request_cookies["z_ddos_captcha"] or ""
	-- split the cookie up
	local split_cookie = utils.split(received_captcha_cookie, "#")
	if #split_cookie ~= 3 then
		return
	end
	local given_user_key = split_cookie[1]
	local given_user_hash = split_cookie[2]
	local given_signature = split_cookie[3]
	-- regenerate the user hash and compare it
	local generated_user_hash = utils.generate_secret(txn, captcha_cookie_secret, given_user_key, false)
	if generated_user_hash ~= given_user_hash then
		return
	end
	-- regenerate the signature and compare it
	local generated_signature = sha.hmac(sha.sha3_256, hmac_cookie_secret, given_user_key .. given_user_hash)
	if given_signature == generated_signature then
		return txn:set_var("txn.captcha_passed", true)
	end
end

-- check if pow cookie is valid
function _M.check_pow_status(txn)
	local parsed_request_cookies = cookie.get_cookie_table(txn.sf:hdr("Cookie"))
	local received_pow_cookie = parsed_request_cookies["z_ddos_pow"] or ""
	-- split the cookie up
	local split_cookie = utils.split(received_pow_cookie, "#")
	if #split_cookie ~= 4 then
		return
	end
	local given_user_key = split_cookie[1]
	local given_challenge_hash = split_cookie[2]
	local given_answer = split_cookie[3]
	local given_signature = split_cookie[4]
	-- regenerate the challenge and compare it
	local generated_challenge_hash = utils.generate_secret(txn, pow_cookie_secret, given_user_key, false)
	if given_challenge_hash ~= generated_challenge_hash then
		return
	end
	-- regenerate the signature and compare it
	local generated_signature = sha.hmac(sha.sha3_256, hmac_cookie_secret, given_user_key .. given_challenge_hash .. given_answer)
	if given_signature == generated_signature then
		return txn:set_var("txn.pow_passed", true)
	end
end

return _M
