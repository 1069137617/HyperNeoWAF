-- WAF 配置加载器
-- 从 Redis 加载配置并缓存，支持默认值

local redis_pool = require "lib.redis_pool"

local _M = {}
local _cache = {}
local _cache_ttl = 60 -- 缓存有效期（秒）
local _last_update = 0

-- 获取配置值，未找到时返回默认值
function _M.get(key, default)
    -- 优先使用缓存
    if _cache[key] and (ngx.now() - _last_update) < _cache_ttl then
        return _cache[key]
    end

    -- 尝试从 Redis 加载
    local redis_key = "waf:config:" .. key
    local value, err = redis_pool.execute("GET", redis_key)

    if value ~= ngx.null and value ~= nil then
        _cache[key] = value
        _last_update = ngx.now()
        return value
    end

    -- 返回默认值
    return default
end

-- 从 Redis 批量加载所有配置到缓存
function _M.load()
    local keys, err = redis_pool.execute("KEYS", "waf:config:*")
    if not keys or #keys == 0 then
        ngx.log(ngx.INFO, "Redis 中无配置，使用默认值")
        return true
    end

    -- 使用管道批量加载
    local commands = {}
    for _, key in ipairs(keys) do
        table.insert(commands, {"GET", key})
    end

    local results, pipe_err = redis_pool.pipeline(commands)
    if not results then
        ngx.log(ngx.ERR, "从 Redis 批量加载配置失败: ", pipe_err)
        return false
    end

    -- 更新缓存
    _cache = {}
    for i, key in ipairs(keys) do
        -- 从 Redis key 中提取配置键名（去掉前缀）
        local config_key = string.sub(key, #"waf:config:" + 1)
        if results[i] ~= ngx.null then
            _cache[config_key] = results[i]
        end
    end

    _last_update = ngx.now()
    ngx.log(ngx.INFO, "已从 Redis 加载 ", #_cache, " 条配置")

    return true
end

-- 强制刷新缓存
function _M.refresh()
    _cache = {}
    _last_update = 0
    return _M.load()
end

-- 设置配置值到 Redis 并更新缓存
function _M.set(key, value)
    local redis_key = "waf:config:" .. key
    local ok, err = redis_pool.execute("SET", redis_key, value)

    if ok then
        _cache[key] = value
        _last_update = ngx.now()
    else
        ngx.log(ngx.ERR, "设置配置 [", key, "] 失败: ", err)
    end

    return ok, err
end

return _M