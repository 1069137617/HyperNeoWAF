-- Redis 连接池管理器
-- 提供连接池和 keepalive 支持
-- 使用 lua-resty-redis 库

local redis_lib = require "resty.redis"
local config = require "lib.config"

local _M = {}
local _pool_config = nil

-- 初始化连接池
function _M.init(conf)
    _pool_config = conf or {
        host = config.get("redis.host", "127.0.0.1"),
        port = tonumber(config.get("redis.port", 6379)),
        password = config.get("redis.password", ""),
        db = tonumber(config.get("redis.db", 0)),
        pool_size = tonumber(config.get("redis.pool_size", 100)),
        keepalive_timeout = tonumber(config.get("redis.keepalive_timeout", 10000)),
    }

    ngx.log(ngx.INFO, "Redis 连接池已初始化: ", _pool_config.host, ":", _pool_config.port)
end

-- 从连接池获取连接或创建新连接
function _M.get_connection()
    local red = redis_lib:new()
    red:set_timeouts(1000, 1000, 1000) -- 连接、发送、读取超时（毫秒）

    local ok, err = red:connect(_pool_config.host, _pool_config.port)
    if not ok then
        ngx.log(ngx.ERR, "Redis 连接失败: ", err)
        return nil, err
    end

    -- 如果设置了密码则认证
    if _pool_config.password and _pool_config.password ~= "" then
        local auth_ok, auth_err = red:auth(_pool_config.password)
        if not auth_ok then
            ngx.log(ngx.ERR, "Redis 认证失败: ", auth_err)
            return nil, auth_err
        end
    end

    -- 如果不是默认数据库则切换
    if _pool_config.db and _pool_config.db > 0 then
        local select_ok, select_err = red:select(_pool_config.db)
        if not select_ok then
            ngx.log(ngx.ERR, "Redis 切换数据库失败: ", select_err)
            return nil, select_err
        end
    end

    return red
end

-- 释放连接回连接池（keepalive）
function _M.release_connection(red)
    if not red then
        return
    end

    local ok, err = red:set_keepalive(
        _pool_config.keepalive_timeout,
        _pool_config.pool_size
    )

    if not ok then
        ngx.log(ngx.WARN, "设置 keepalive 失败: ", err)
        red:close()
    end
end

-- 执行命令（自动管理连接）
function _M.execute(command, ...)
    local red, conn_err = _M.get_connection()
    if not red then
        return nil, conn_err
    end

    local result, err = red(command, ...)
    _M.release_connection(red)

    if err then
        ngx.log(ngx.ERR, "Redis 命令执行失败 [", command, "]: ", err)
        return nil, err
    end

    return result
end

-- 执行管道命令（自动管理连接）
function _M.pipeline(commands)
    local red, conn_err = _M.get_connection()
    if not red then
        return nil, conn_err
    end

    red:init_pipeline()
    for _, cmd in ipairs(commands) do
        red(unpack(cmd))
    end

    local results, err = red:commit_pipeline()
    _M.release_connection(red)

    if err then
        ngx.log(ngx.ERR, "Redis 管道执行失败: ", err)
        return nil, err
    end

    return results
end

-- 健康检查
function _M.health_check()
    local result, err = _M.execute("ping")
    if not result then
        return false, err
    end
    return result == "PONG"
end

return _M