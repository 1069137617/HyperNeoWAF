-- WAF 日志记录器入口
-- 在 log_by_lua 阶段调用
-- 收集安全事件并异步发送到 Go 后端

local logger = require "log.logger"

local _M = {}

function _M.run()
    -- 仅记录触发了 WAF 动作的请求
    local waf_action = ngx.ctx.waf_action
    if not waf_action then
        return
    end

    local log_entry = {
        timestamp = ngx.now(),
        client_ip = ngx.var.remote_addr,
        method = ngx.req.get_method(),
        uri = ngx.var.uri,
        status = ngx.status,
        user_agent = ngx.var.http_user_agent or "",
        referer = ngx.var.http_referer or "",
        waf_action = waf_action,
        waf_rule = ngx.ctx.waf_rule or "",
        request_time = ngx.var.request_time,
    }

    -- 异步发送日志条目到 Go 后端
    logger.send(log_entry)
end

return _M