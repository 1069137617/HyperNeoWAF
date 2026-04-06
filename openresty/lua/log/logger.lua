-- WAF 异步日志记录器
-- 收集安全事件并发送到 Go 后端
-- 实现本地文件回退以提高可靠性

local cjson = require "cjson.safe"
local masking = require "lib.masking"
local config = require "lib.config"

local _M = {}
local _backend_url = nil
local _log_buffer = {}
local _buffer_size = 100 -- 刷新前的最大缓冲日志数
local _flush_interval = 5 -- 自动刷新间隔（秒）
local _last_flush = 0

-- 使用后端 URL 初始化日志记录器
function _M.init(backend_url)
    _backend_url = backend_url or config.get("logging.backend_url", "http://127.0.0.1:8080/api/v1/logs/receive")
    _buffer_size = tonumber(config.get("logging.buffer_size", 100)) or 100
    _flush_interval = tonumber(config.get("logging.flush_interval", 5)) or 5

    ngx.log(ngx.INFO, "日志记录器已初始化，后端: ", _backend_url)
end

-- 从当前请求上下文构建日志条目
function _M.build_log_entry(extra_data)
    -- 收集请求数据
    local entry = {
        timestamp = ngx.now(),
        timestamp_iso = os.date("!%Y-%m-%dT%H:%M:%SZ", ngx.time()),

        -- 客户端信息（已脱敏）
        client_ip = masking.mask_field("ip", ngx.var.remote_addr),

        -- 请求详情
        method = ngx.req.get_method(),
        uri = masking.mask_field("uri", ngx.var.uri),
        args = masking.mask_field("args", ngx.var.args or ""),
        protocol = ngx.var.server_protocol,

        -- 请求头（选择性记录和脱敏）
        headers = {
            host = ngx.var.host,
            user_agent = masking.mask_field("user_agent", ngx.var.http_user_agent or ""),
            referer = masking.mask_field("referer", ngx.var.http_referer or ""),
            content_type = ngx.var.content_type or "",
            accept_language = ngx.var.http_accept_language or "",
        },

        -- 响应信息
        status_code = ngx.status,

        -- WAF 特定数据
        waf_action = ngx.ctx.waf_action or "allow",
        waf_rule = ngx.ctx.waf_rule or "",
        waf_reason = ngx.ctx.waf_reason or "",

        -- 限流信息（如适用）
        rate_limit_current = ngx.ctx.rate_limit_current,
        rate_limit_max = ngx.ctx.rate_limit_max,
        rate_limit_reason = ngx.ctx.rate_limit_reason,

        -- 性能指标
        request_time = tonumber(ngx.var.request_time) or 0,
        bytes_sent = tonumber(ngx.var.bytes_sent) or 0,
        body_bytes_sent = tonumber(ngx.var.body_bytes_sent) or 0,

        -- 调用者提供的额外上下文
        extra = extra_data or {},
    }

    -- 如果请求则对 body 内容进行脱敏
    if entry.extra.log_body then
        ngx.req.read_body()
        local raw_body = ngx.req.get_body_data()
        if raw_body then
            entry.body = masking.mask_table(cjson.decode(raw_body) or {raw = raw_body})
        end
        entry.extra.log_body = nil -- 处理后移除标志
    end

    return entry
end

-- 将日志条目添加到缓冲区（非阻塞）
function _M.send(log_entry)
    if not log_entry then
        log_entry = _M.build_log_entry()
    end

    table.insert(_log_buffer, log_entry)

    -- 缓冲区满时自动刷新
    if #_log_buffer >= _buffer_size then
        _flush()
    end
end

-- 将所有缓冲日志刷新到后端
function _flush()
    if #_log_buffer == 0 then
        return true
    end

    local logs_to_send = _log_buffer
    _log_buffer = {} -- 立即清空缓冲区

    local payload = cjson.encode({
        source = "openresty-waf",
        timestamp = ngx.now(),
        count = #logs_to_send,
        logs = logs_to_send,
    })

    -- 使用 ngx.timer 异步发送
    local ok, err = ngx.timer.at(0, function(premature)
        if premature then
            return
        end

        _send_to_backend(payload)
    end)

    if not ok then
        ngx.log(ngx.ERR, "创建异步计时器失败: ", err)
        -- 回退：写入本地文件
        _write_to_local_file(logs_to_send)
        return false
    end

    _last_flush = ngx.now()
    return true
end

-- 通过 HTTP POST 发送数据到 Go 后端
function _send_to_backend(payload)
    local http = require "resty.http"
    local httpc = http.new()

    local timeout = tonumber(config.get("logging.timeout", 2)) or 2
    httpc:set_timeouts(timeout * 1000, timeout * 1000, timeout * 1000) -- 毫秒

    local ok, conn_err = httpc:connect(_backend_url:match("^http://([^/]+)") or "127.0.0.1:8080")

    if not ok then
        ngx.log(ngx.ERR, "连接日志后端失败: ", conn_err)
        -- 回退到本地文件
        _write_to_local_file(cjson.decode(payload).logs)
        return false
    end

    local res, err = httpc:request({
        method = "POST",
        path = "/api/v1/logs/receive",
        body = payload,
        headers = {
            ["Content-Type"] = "application/json",
            ["X-WAF-Source"] = "openresty",
            ["X-WAF-Count"] = tostring(#(cjson.decode(payload).logs)),
        },
    })

    if not res then
        ngx.log(ngx.ERR, "发送日志到后端失败: ", err)
        _write_to_local_file(cjson.decode(payload).logs)
        httpc:close()
        return false
    end

    -- 检查响应状态
    if res.status >= 200 and res.status < 300 then
        ngx.log(ngx.DEBUG, "成功发送 ", #(cjson.decode(payload).logs), " 条日志到后端")
    else
        ngx.log(ngx.WARN, "后端返回状态 ", res.status, " 用于日志提交")
        local reader = res.body_reader()
        local body, read_err = reader(65536)
        if body then
            ngx.log(ngx.DEBUG, "后端响应: ", body)
        end
        -- 非 2xx 响应时回退
        _write_to_local_file(cjson.decode(payload).logs)
    end

    httpc:close()
    return true
end

-- 回退时将日志写入本地文件
function _write_to_local_file(logs)
    if not logs or #logs == 0 then
        return
    end

    local log_dir = config.get("logging.local_dir", "/var/log/waf/")
    local log_filename = os.date("%Y-%m-%d") .. "_fallback.log"
    local full_path = log_dir .. log_filename

    -- 确保目录存在（使用追加模式打开 io.open 如果目录不存在会失败）
    -- 生产环境应预先确保此目录存在

    local file, open_err = io.open(full_path, "a")
    if not file then
        ngx.log(ngx.ERR, "无法打开回退日志文件: ", open_err)
        return false
    end

    for _, entry in ipairs(logs) do
        local line = cjson.encode(entry) .. "\n"
        file:write(line)
    end

    file:close()

    ngx.log(ngx.INFO, "将 ", #logs, " 条日志写入回退文件: ", full_path)
    return true
end

-- 定期刷新（从 log_by_lua 阶段调用）
function _M.periodic_flush()
    local now = ngx.now()
    if (#_log_buffer > 0) and ((now - _last_flush) >= _flush_interval) then
        _flush()
    end
end

-- 获取缓冲区统计信息（用于监控）
function _M.get_stats()
    return {
        buffer_count = #_log_buffer,
        buffer_capacity = _buffer_size,
        last_flush = _last_flush,
        flush_interval = _flush_interval,
    }
end

return _M