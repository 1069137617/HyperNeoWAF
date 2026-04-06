-- IP 黑名单/白名单检查模块
-- 检查客户端 IP 是否在 Redis 存储的黑名单和白名单中

local redis_pool = require "lib.redis_pool"
local cjson = require "cjson.safe"

local _M = {}
local _blacklist_cache = {}
local _whitelist_cache = {}
local _cache_ttl = 30 -- 缓存有效期（秒）
local _last_update = 0

-- 检查 IP 是否在黑名单中
function _M.is_blocked(ip)
    -- 优先检查白名单
    if _M.is_whitelisted(ip) then
        return false
    end

    -- 检查缓存
    local now = ngx.now()
    if (now - _last_update) > _cache_ttl then
        _refresh_cache()
    end

    -- 精确匹配检查
    if _blacklist_cache[ip] then
        ngx.log(ngx.WARN, "IP 被拦截（精确匹配）: ", ip)
        return true
    end

    -- CIDR 范围检查（简化版 - 完整实现需使用 lua-resty-ipmatcher）
    for cidr, _ in pairs(_blacklist_cache) do
        if string.match(cidr, "/") and _ip_in_cidr(ip, cidr) then
            ngx.log(ngx.WARN, "IP 被拦截（CIDR 匹配）: ", ip, " 属于 ", cidr)
            return true
        end
    end

    return false
end

-- 检查 IP 是否在白名单中
function _M.is_whitelisted(ip)
    local now = ngx.now()
    if (now - _last_update) > _cache_ttl then
        _refresh_cache()
    end

    -- 精确匹配
    if _whitelist_cache[ip] then
        return true
    end

    -- CIDR 匹配
    for cidr, _ in pairs(_whitelist_cache) do
        if string.match(cidr, "/") and _ip_in_cidr(ip, cidr) then
            return true
        end
    end

    return false
end

-- 添加 IP 到黑名单
function _M.add_to_blacklist(ip, reason, expire_seconds)
    local redis_key = "waf:blacklist:" .. ip
    local data = cjson.encode({
        ip = ip,
        reason = reason or "Manual block",
        added_at = ngx.now(),
        added_by = "waf_engine",
    })

    local ok, err
    if expire_seconds and expire_seconds > 0 then
        ok, err = redis_pool.execute("SETEX", redis_key, expire_seconds, data)
    else
        ok, err = redis_pool.execute("SET", redis_key, data)
    end

    if ok then
        _blacklist_cache[ip] = data
        ngx.log(ngx.INFO, "添加黑名单: ", ip, " (", reason, ")")
    else
        ngx.log(ngx.ERR, "添加黑名单失败: ", err)
    end

    return ok, err
end

-- 从黑名单移除 IP
function _M.remove_from_blacklist(ip)
    local redis_key = "waf:blacklist:" .. ip
    local ok, err = redis_pool.execute("DEL", redis_key)

    if ok then
        _blacklist_cache[ip] = nil
        ngx.log(ngx.INFO, "从黑名单移除: ", ip)
    end

    return ok, err
end

-- 获取所有黑名单 IP（供管理界面显示）
function _M.get_blacklist()
    local keys, err = redis_pool.execute("KEYS", "waf:blacklist:*")
    if not keys or #keys == 0 then
        return {}
    end

    local results, pipe_err = redis_pool.pipeline(
        (function()
            local cmds = {}
            for _, key in ipairs(keys) do
                table.insert(cmds, {"GET", key})
            end
            return cmds
        end)()
    )

    if not results then
        ngx.log(ngx.ERR, "获取黑名单失败: ", pipe_err)
        return {}
    end

    local list = {}
    for i, key in ipairs(keys) do
        if results[i] ~= ngx.null then
            local entry = cjson.decode(results[i])
            if entry then
                table.insert(list, entry)
            end
        end
    end

    return list
end

-- 从 Redis 刷新本地缓存
function _refresh_cache()
    -- 加载黑名单
    local bl_keys, bl_err = redis_pool.execute("KEYS", "waf:blacklist:*")
    if bl_keys and #bl_keys > 0 then
        local bl_results, _ = redis_pool.pipeline((function()
            local cmds = {}
            for _, k in ipairs(bl_keys) do
                table.insert(cmds, {"GET", k})
            end
            return cmds
        end)())

        _blacklist_cache = {}
        if bl_results then
            for i, key in ipairs(bl_keys) do
                if bl_results[i] ~= ngx.null then
                    -- 从 key 中提取 IP
                    local ip = string.sub(key, #"waf:blacklist:" + 1)
                    _blacklist_cache[ip] = bl_results[i]
                end
            end
        end
    else
        _blacklist_cache = {}
    end

    -- 加载白名单
    local wl_keys, wl_err = redis_pool.execute("KEYS", "waf:whitelist:*")
    if wl_keys and #wl_keys > 0 then
        local wl_results, _ = redis_pool.pipeline((function()
            local cmds = {}
            for _, k in ipairs(wl_keys) do
                table.insert(cmds, {"GET", k})
            end
            return cmds
        end)())

        _whitelist_cache = {}
        if wl_results then
            for i, key in ipairs(wl_keys) do
                if wl_results[i] ~= ngx.null then
                    local ip = string.sub(key, #"waf:whitelist:" + 1)
                    _whitelist_cache[ip] = wl_results[i]
                end
            end
        end
    else
        _whitelist_cache = {}
    end

    _last_update = ngx.now()
end

-- 简单的 CIDR 匹配（仅支持 IPv4，生产环境应使用专业库）
function _ip_in_cidr(ip, cidr)
    -- 这是一个简化实现
    -- 生产环境应使用 lua-resty-ipmatcher 库
    local network, bits_str = string.match(cidr, "^([%d%.]+)/(%d+)$")

    if not network or not bits_str then
        return false
    end

    local bits = tonumber(bits_str)
    if not bits or bits < 0 or bits > 32 then
        return false
    end

    -- 将 IP 转换为数字
    local ip_num = _ip_to_number(ip)
    local net_num = _ip_to_number(network)

    if not ip_num or not net_num then
        return false
    end

    local mask = bit.lshift(0xFFFFFFFF, (32 - bits)) % 0x100000000
    return bit.band(ip_num, mask) == bit.band(net_num, mask)
end

-- 将 IPv4 地址转换为数字
function _ip_to_number(ip)
    local o1, o2, o3, o4 = string.match(ip, "^(%d+)%.(%d+)%.(%d+)%.(%d+)$")

    if not o1 or not o2 or not o3 or not o4 then
        return nil
    end

    return (tonumber(o1) * 16777216) +
           (tonumber(o2) * 65536) +
           (tonumber(o3) * 256) +
           tonumber(o4)
end

return _M