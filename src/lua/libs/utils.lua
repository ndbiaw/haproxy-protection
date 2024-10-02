local _M = {}
local sha = require("sha")
local tor_control_port_password = os.getenv("TOR_CONTROL_PORT_PASSWORD")

-- get header from different place depending on action vs view
function _M.get_header_from_context(context, header_name, is_applet)
	local header_content = ""
	if is_applet == true then
		header_content = context.headers[header_name] or {}
		header_content = header_content[0] or ""
	else
		header_content = context.sf:req_fhdr(header_name) or ""
	end
	return header_content
end

-- generate the challenge hash/user hash
function _M.generate_challenge(context, salt, user_key, ddos_config, is_applet)

	-- optional IP to lock challenges/user_keys to IP (for clearnet or single-onion aka 99% of cases)
	local ip = ""
	if ddos_config["cip"] == true then
		ip = context.sf:src()
	end

	-- user agent to counter very dumb spammers
	local user_agent = _M.get_header_from_context(context, "user-agent", is_applet)

	local challenge_hash = sha.sha3_256(salt .. ip .. user_key .. user_agent)

	local expiry = core.now()["sec"] + ddos_config["cex"]

	return challenge_hash, expiry

end

-- split string by delimiter
function _M.split(inputstr, sep)
	local t = {}
	for str in string.gmatch(inputstr, "([^"..sep.."]*)") do
		table.insert(t, str)
	end
	return t
end

-- check if elem in list
function _M.contains(list, elem)
	for _, v in pairs(list) do
		if v == elem then return true end
	end
	return false
end

-- return true if hash passes difficulty
function _M.checkdiff(hash, diff)
	if #hash == 0 then
		return false
	end
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
	tcp:connect("127.0.0.1", 9051); --TODO: configurable host/port
	-- not buffered, so we are better off sending it all at once
	tcp:send('AUTHENTICATE "' .. tor_control_port_password .. '"\nCLOSECIRCUIT ' .. circuit_identifier ..'\n')
	tcp:close()
end

return _M
