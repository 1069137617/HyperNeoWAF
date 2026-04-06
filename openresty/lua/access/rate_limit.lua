-- 限流模块
-- 使用 Redis Lua 脚本实现原子性限流
-- 支持多维度：IP、URL、User-Agent

local redis_pool = require "lib.redis_pool"
local config = require "lib.config"

local _M = {}

-- Lua 脚本：原子性增量计数（滑动窗口）
-- KEYS[1]: 限流 key
-- ARGV[1]: 时间窗口（秒）
-- ARGV[2]: 最大请求数
-- 返回: {current_count, ttl}
local rate_limit_script = [[
    local current = tonumber(redis.call('INCR', KEYS[1]))

    if current == 1 then
        redis.call('EXPIRE', KEYS[1], ARGV[1])
    end

    local ttl = redis.call('TTL', KEYS[1])

    return {current, ttl}
]]

-- 缓存的脚本 SHA（用于提升性能）
local _script_sha = nil

-- 获取或加载限流脚本
function _get_script_sha()
    if _script_sha then
        return _script_sha
    end

    local sha, err = redis_pool.execute("SCRIPT", "LOAD", rate_limit_script)
    if sha then
        _script_sha = sha
    end

    return sha, err
end

-- 检查限流
-- 返回 true 表示超过限制，false 表示正常
function _M.check(key, max_requests, window_seconds)
    if not max_requests then
        max_requests = tonumber(config.get("ratelimit.default.max_requests", 100))
    end
    if not window_seconds then
        window_seconds = tonumber(config.get("ratelimit.default.window", 60))
    end

    local redis_key = "waf:ratelimit:" .. key
    local sha, sha_err = _get_script_sha()

    if not sha then
        -- 如果脚本加载失败，回退到基础 INCR 方式
        ngx.log(ngx.ERR, "加载限流脚本失败: ", sha_err)
        return _fallback_check(redis_key, max_requests, window_seconds)
    end

    local result, err = redis_pool.execute("EVALSHA", sha, 1,
                                            redis_key,
                                            tostring(window_seconds),
                                            tostring(max_requests))

    if not result then
        ngx.log(ngx.ERR, "限流检查失败: ", err)
        return false -- 失败时放行（fail-open）
    end

    local current_count = tonumber(result[1]) or 0
    local ttl = tonumber(result[2]) or 0

    -- 存储信息到 nginx 上下文用于日志记录
    ngx.ctx.rate_limit_current = current_count
    ngx.ctx.rate_limit_max = max_requests
    ngx.ctx.rate_limit_ttl = ttl

    if current_count > max_requests then
        ngx.log(ngx.WARN, "请求过于频繁 [", key, "]: ",
                current_count, "/", max_requests, " (ttl: ", ttl, "s)")
        return true
    end

    return false
end

-- 回退方法（当 EVALSHA 失败时使用）
function _fallback_check(key, max_requests, window)
    local current, err = redis_pool.execute("INCR", key)

    if not current then
        ngx.log(ngx.ERR, "回退限流检查失败: ", err)
        return false
    end

    current = tonumber(current)

    if current == 1 then
        redis_pool.execute("EXPIRE", key, window)
    end

    ngx.ctx.rate_limit_current = current
    ngx.ctx.rate_limit_max = max_requests

    return current > max_requests
end

-- 按 IP 地址检查限流（最常用场景）
function _M.check_ip(client_ip)
    local max_req = tonumber(config.get("ratelimit.ip.max_requests", 60))
    local window = tonumber(config.get("ratelimit.ip.window", 60))

    return _M.check("ip:" .. client_ip, max_req, window)
end

-- 按 URL 路径检查限流
function _M.check_url(url, client_ip)
    local max_req = tonumber(config.get("ratelimit.url.max_requests", 120))
    local window = tonumber(config.get("ratelimit.url.window", 60))

    -- 标准化 URL（去除查询字符串以便分组）
    local normalized_url = string.match(url, "^([^?]+)") or url

    return _M.check("url:" .. normalized_url .. ":" .. client_ip, max_req, window)
end

-- 按 User-Agent 检查限流（检测机器人活动）
function _M.check_ua(user_agent, client_ip)
    -- 仅对可疑的 UA 进行检查（可选优化）
    local max_req = tonumber(config.get("ratelimit.ua.max_requests", 200))
    local window = tonumber(config.get("ratelimit.ua.window", 60))

    -- 对 UA 进行哈希或截断以避免过长的 key
    local ua_key = user_agent or "unknown"
    if #ua_key > 64 then
        ua_key = string.sub(ua_key, 1, 64)
    end

    return _M.check("ua:" .. ua_key .. ":" .. client_ip, max_req, window)
end

-- 综合检查：IP + URL + UA（全面防护）
function _M.check_comprehensive(client_ip, url, user_agent)
    -- 首先检查基于 IP 的限制（最快拒绝）
    if _M.check_ip(client_ip) then
        ngx.ctx.rate_limit_reason = "ip"
        return true
    end

    -- 检查基于 URL 的限制
    if _M.check_url(url, client_ip) then
        ngx.ctx.rate_limit_reason = "url"
        return true
    end

    -- 检查基于 UA 的限制（较少触发）
    if _M.check_ua(user_agent, client_ip) then
        ngx.ctx.rate_limit_reason = "ua"
        return true
    end

    return false
end

-- 获取剩余配额信息（用于响应头）
function _M.get_rate_limit_info()
    return {
        limit = ngx.ctx.rate_limit_max or 0,
        remaining = math.max(0, (ngx.ctx.rate_limit_max or 0) - (ngx.ctx.rate_limit_current or 0)),
        reset = ngx.ctx.rate_limit_ttl or 0,
    }
end

-- 设置限流响应头
function _M.set_response_headers()
    local info = _M.get_rate_limit_info()

    if info.limit > 0 then
        ngx.header["X-RateLimit-Limit"] = tostring(info.limit)
        ngx.header["X-RateLimit-Remaining"] = tostring(info.remaining)
        ngx.header["X-RateLimit-Reset"] = tostring(info.reset)
    end
end

return _M