package.path = package.path  .. "./?.lua;/etc/haproxy/scripts/?.lua;/etc/haproxy/libs/?.lua"

local pow_difficulty = tonumber(os.getenv("POW_DIFFICULTY") or 18)
local backends_map = Map.new('/etc/haproxy/map/backends.map', Map._str)
local utils = require("utils")

-- setup initial server backends based on hosts.map
function setup_servers()
	if pow_difficulty < 8 then
		error("POW_DIFFICULTY must be > 8. Around 16-32 is better")
	end
	local backend_name = os.getenv("BACKEND_NAME")
	local server_prefix = os.getenv("SERVER_PREFIX")
	if backend_name == nil or server_prefix == nil then
		return;
	end
	local handle = io.open("/etc/haproxy/map/hosts.map", "r")
	local line = handle:read("*line")
	local verify_backend_ssl = os.getenv("VERIFY_BACKEND_SSL")
	local counter = 1
	-- NOTE: using tcp socket to interact with runtime API because lua can't add servers
	local tcp = core.tcp();
	tcp:settimeout(10);
	tcp:connect("127.0.0.1", 2000); --TODO: configurable port
	while line do
		local domain, backend_host = line:match("([^%s]+)%s+([^%s]+)")
		local new_map_value = server_prefix..counter
		local existing_map_value = backends_map:lookup(domain)
		if existing_map_value ~= nil then
			current_backends = utils.split(existing_map_value, ",")
			if not utils.contains(current_backends, new_map_value) then
				new_map_value = new_map_value .. "," .. existing_map_value
			end
		end
		print("setting hosts.map "..domain.." "..new_map_value)
		core.set_map("/etc/haproxy/map/backends.map", domain, new_map_value)
		local server_name = "servers/websrv"..counter
		--NOTE: if you have a proper CA setup,
		if verify_backend_ssl ~= nil then
			tcp:send(string.format("add server %s %s check ssl verify required ca-file ca-certificates.crt sni req.hdr(Host);", server_name, backend_host))
		else
			tcp:send(string.format("add server %s %s;", server_name, backend_host))
		end
		tcp:send(string.format("enable server %s;", server_name))
		line = handle:read("*line")
		counter = counter + 1
	end
	handle:close()
   	tcp:close()
end

core.register_task(setup_servers)
