local _M = {}

local sha = require("sha")
local secret_bucket_duration = tonumber(os.getenv("BUCKET_DURATION"))
local challenge_includes_ip = os.getenv("CHALLENGE_INCLUDES_IP")
local tor_control_port_password = os.getenv("TOR_CONTROL_PORT_PASSWORD")

-- generate the challenge hash/user hash
function _M.generate_secret(context, salt, user_key, is_applet)

	-- time bucket for expiry
	local start_sec = core.now()['sec']
	local bucket = start_sec - (start_sec % secret_bucket_duration)

	-- optional IP to lock challenges/user_keys to IP (for clearnet or single-onion aka 99% of cases)
	local ip = ""
	if challenge_includes_ip == "1" then
		ip = context.sf:src()
	end

	-- user agent to counter very dumb spammers
	local user_agent = ""
	if is_applet == true then
		user_agent = context.headers['user-agent'] or {}
		user_agent = user_agent[0] or ""
	else
		--note req_fhdr not req_hdr otherwise commas in useragent become a delimiter
		user_agent = context.sf:req_fhdr('user-agent') or ""
	end

	return sha.sha3_256(salt .. bucket .. ip .. user_key .. user_agent)

end

-- split string by delimiter
function _M.split(inputstr, sep)
	local t = {}
	for str in string.gmatch(inputstr, "([^"..sep.."]*)") do
		table.insert(t, str)
	end
	return t
end

-- return true if hash passes difficulty
function _M.checkdiff(hash, diff)
	local i = 1
	for j = 0, (diff-8), 8 do
		if hash:sub(i, i) ~= "0" then
			return false
		end
		i = i + 1
	end
	local lnm = tonumber(hash:sub(i, i), 16)
	local msk = 0xff >> ((i*8)-diff)
	return (lnm & msk) == 0
end

-- connect to the tor control port and instruct it to close a circuit
function _M.send_tor_control_port(circuit_identifier)
	local tcp = core.tcp();
	tcp:settimeout(1);
	tcp:connect("127.0.0.1", 9051);
	-- not buffered, so we are better off sending it all at once
	tcp:send('AUTHENTICATE "' .. tor_control_port_password .. '"\nCLOSECIRCUIT ' .. circuit_identifier ..'\n')
	tcp:close()
end

return _M

