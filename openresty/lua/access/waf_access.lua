-- WAF 访问控制入口
-- 在 access_by_lua 阶段调用
-- 在转发到后端之前协调所有安全检查

local ip_check = require "access.ip_check"
local rate_limit = require "access.rate_limit"
local rule_engine = require "filter.rule_engine"

local _M = {}

function _M.run()
    local client_ip = ngx.var.remote_addr

    -- 1. IP 黑名单检查
    if ip_check.is_blocked(client_ip) then
        ngx.log(ngx.WARN, "IP 被拦截: ", client_ip)
        ngx.status = 403
        ngx.say('{"error": "Forbidden", "reason": "IP blacklisted"}')
        ngx.exit(403)
        return
    end

    -- 2. 限流检查
    if rate_limit.check(client_ip) then
        ngx.log(ngx.WARN, "IP 请求过于频繁: ", client_ip)
        ngx.status = 429
        ngx.header["Retry-After"] = "60"
        ngx.say('{"error": "Too Many Requests", "reason": "Rate limit exceeded"}')
        ngx.exit(429)
        return
    end

    -- 3. 规则引擎检测（SQL注入、XSS、CC攻击等）
    local method = ngx.req.get_method()
    local uri = ngx.var.uri
    local headers = ngx.req.get_headers()

    -- 仅对 POST/PUT/PATCH 请求检查 body
    local body = nil
    if method == "POST" or method == "PUT" or method == "PATCH" then
        ngx.req.read_body()
        body = ngx.req.get_body_data()
    end

    local match_result = rule_engine.match(method, uri, headers, body)
    if match_result then
        ngx.log(ngx.WARN, "规则命中: ", match_result.rule_name, " 来源 IP: ", client_ip)
        ngx.status = match_result.action == "deny" and 403 or 200
        ngx.ctx.waf_action = match_result.action
        ngx.ctx.waf_rule = match_result.rule_name

        if match_result.action == "deny" then
            ngx.say('{"error": "Forbidden", "reason": "' .. match_result.reason .. '"}')
            ngx.exit(403)
            return
        end
    end

    -- 所有检查通过，允许请求继续
    ngx.log(ngx.INFO, "请求放行，来源 IP: ", client_ip)
end

return _M