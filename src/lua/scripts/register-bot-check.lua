package.path = package.path  .. "./?.lua;/etc/haproxy/scripts/?.lua;/etc/haproxy/libs/?.lua"

local bot_check = require("bot-check")
local utils = require("utils")

local backends_map = Map.new('/etc/haproxy/map/backends.map', Map._str)
function get_server_names(txn)
    local key = txn.sf:hdr("Host")
    local value = backends_map:lookup(key or "")
    if value ~= nil then
        local vals = utils.split(value, ",")
        -- todo: something smarter?
        return vals[math.random(#vals)]
    else
        return ""
    end
end

core.register_fetches("get_server_names", get_server_names)
core.register_service("bot-check", "http", bot_check.view)
core.register_action("captcha-check", { 'http-req', }, bot_check.check_captcha_status)
core.register_action("pow-check", { 'http-req', }, bot_check.check_pow_status)
core.register_action("decide-checks-necessary", { 'http-req', }, bot_check.decide_checks_necessary)
core.register_action("kill-tor-circuit", { 'http-req', }, bot_check.kill_tor_circuit)
core.register_action("set-lang-json", { 'http-req', }, bot_check.set_lang_json)
core.register_action("set-ip-var", { 'http-req', }, bot_check.set_ip_var, 3)
