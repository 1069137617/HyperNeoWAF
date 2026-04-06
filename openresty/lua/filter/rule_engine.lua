-- WAF 规则引擎
-- 从 Redis 加载安全规则并对传入请求进行匹配
-- 检测 SQL 注入、XSS、CC 攻击、路径遍历等

local redis_pool = require "lib.redis_pool"
local cjson = require "cjson.safe"

local _M = {}
local _rules_cache = {}
local _cache_ttl = 10 -- 缓存有效期（秒，较短以便快速更新规则）
local _last_update = 0

-- 规则类型枚举
local RULE_TYPES = {
    SQL_INJECTION = "sql_injection",
    XSS = "xss",
    CC_ATTACK = "cc_attack",
    PATH_TRAVERSAL = "path_traversal",
    COMMAND_INJECTION = "command_injection",
    SSI_INJECTION = "ssi_injection",
    XXE_INJECTION = "xxe_injection",
    CUSTOM_REGEX = "custom_regex",
}

-- 动作类型
local ACTIONS = {
    DENY = "deny",
    ALLOW = "allow",
    LOG_ONLY = "log_only",
}

-- 初始化规则引擎（启动时加载规则）
function _M.init()
    _load_rules()
    ngx.log(ngx.INFO, "规则引擎已初始化，共 ", #_rules_cache, " 条规则")
end

-- 对单个请求进行所有启用规则的匹配
function _M.match(method, uri, headers, body)
    -- 必要时刷新规则缓存
    local now = ngx.now()
    if (now - _last_update) > _cache_ttl then
        _load_rules()
    end

    -- 构建用于匹配的请求上下文
    local request_context = {
        method = method,
        uri = uri,
        args = ngx.var.args or "",
        headers = headers or {},
        body = body or "",
        content_type = headers["Content-Type"] or "",
        user_agent = headers["User-Agent"] or "",
        cookie = headers["Cookie"] or "",
    }

    -- 遍历所有启用的规则（按优先级排序）
    for _, rule in ipairs(_rules_cache) do
        if rule.enabled then
            local match_result = _evaluate_rule(rule, request_context)
            if match_result then
                ngx.log(ngx.WARN, "规则命中: ", rule.name,
                        " [类型=", rule.type, "] ",
                        "[动作=", rule.action, "] ",
                        "[模式=", rule.pattern, "]")

                return {
                    rule_id = rule.id,
                    rule_name = rule.name,
                    rule_type = rule.type,
                    action = rule.action,
                    reason = rule.description or "Security rule violation",
                    severity = rule.severity or "medium",
                    matched_pattern = match_result,
                }
            end
        end
    end

    return nil -- 无规则匹配
end

-- 根据规则类型选择评估策略
function _evaluate_rule(rule, ctx)
    local pattern = rule.pattern
    if not pattern then
        return false
    end

    -- 根据规则类型选择评估策略
    local rule_type = rule.type or RULE_TYPES.CUSTOM_REGEX

    if rule_type == RULE_TYPES.SQL_INJECTION then
        return _check_sql_injection(ctx, pattern)
    elseif rule_type == RULE_TYPES.XSS then
        return _check_xss(ctx, pattern)
    elseif rule_type == RULE_TYPES.CC_ATTACK then
        return _check_cc_attack(ctx, pattern)
    elseif rule_type == RULE_TYPES.PATH_TRAVERSAL then
        return _check_path_traversal(ctx, pattern)
    elseif rule_type == RULE_TYPES.COMMAND_INJECTION then
        return _check_command_injection(ctx, pattern)
    else
        -- 默认：对多个字段进行正则匹配
        return _regex_match_any(ctx, pattern)
    end
end

-- SQL 注入检测模式
function _check_sql_injection(ctx, custom_pattern)
    -- 常见 SQL 注入模式
    local sql_patterns = {
        "[%']%s*(OR|AND)%s*[%'0-9]", -- ' OR 1=1
        "(UNION%s+(ALL%s+)?SELECT)", -- UNION SELECT
        "(DROP%s+(TABLE|DATABASE))", -- DROP TABLE
        "(INSERT%s+INTO)", -- INSERT INTO
        "(UPDATE%s+.+%s+SET)", -- UPDATE ... SET
        "(DELETE%s+FROM)", -- DELETE FROM
        "(EXEC(%s|%(.*%))?)", -- EXEC / EXECUTE
        "(WAITFOR%s+DELAY)", -- WAITFOR DELAY
        "(BENCHMARK%()", -- BENCHMARK()
        "(SLEEP%(", -- SLEEP()
        "(LOAD_FILE%()", -- LOAD_FILE()
        "(INTO%s+(OUT|DUMP)FILE)", -- INTO OUTFILE/DUMPFILE
        "(INFORMATION_SCHEMA)", -- 信息架构访问
        "(CONCAT%s*%(.-%.%)", -- CONCAT 使用
        "(CHAR%(%d+'))", -- CHAR() 编码
        "(0x[0-9a-fA-F]+)", -- 十六进制编码
        "--%s*$", -- 末尾注释
        ";%s*--", -- 堆叠查询
        "/%*.-%*/", -- 内联注释
    }

    -- 如果提供了自定义模式则使用，否则使用默认模式
    local patterns_to_check = custom_pattern and {custom_pattern} or sql_patterns

    for _, pattern in ipairs(patterns_to_check) do
        -- 检查 URI
        if _regex_match(ctx.uri, pattern) then
            return pattern
        end

        -- 检查查询参数
        if _regex_match(ctx.args, pattern) then
            return pattern
        end

        -- 检查 body（POST/PUT 请求）
        if ctx.body and _regex_match(ctx.body, pattern) then
            return pattern
        end

        -- 检查 Cookie
        if _regex_match(ctx.cookie, pattern) then
            return pattern
        end
    end

    return false
end

-- XSS 检测模式
function _check_xss(ctx, custom_pattern)
    local xss_patterns = {
        "<%s*script[^>]*>", -- <script> 标签
        "</%s*script%s*>", -- </script> 标签
        "javascript%s*:", -- javascript: 协议
        "on(load|error|click|mouse|focus|blur|key)%s*=", -- 事件处理器
        "<%s*iframe[^>]*>", -- iframe 注入
        "<%s*object[^>]*>", -- object 标签
        "<%s*embed[^>]*>", -- embed 标签
        "<%s*form[^>]*>", -- form 注入
        "expression%s*%(", -- CSS 表达式
        "vbscript%s*:", -- VBScript 协议
        "alert%s*%(", -- alert() 调用
        "document%.cookie", -- Cookie 窃取尝试
        "document%.location", -- 位置操作
        "eval%s*%(", -- eval() 使用
        "fromCharCode", -- 字符串编码混淆
        "%.%.[\"']", -- 属性访问尝试
    }

    local patterns_to_check = custom_pattern and {custom_pattern} or xss_patterns

    for _, pattern in ipairs(patterns_to_check) do
        -- 不区分大小写搜索 XSS
        if _regex_match(ctx.uri, pattern) or
           _regex_match(ctx.args, pattern) or
           (ctx.body and _regex_match(ctx.body, pattern)) then
            return pattern
        end
    end

    return false
end

-- CC 攻击检测（高频相似请求）
function _check_cc_attack(ctx, pattern)
    -- 通常由限流模块处理
    -- 但也可以在此检测特定攻击特征

    local cc_indicators = {
        -- 快速自动化工具特征
        "(python-requests|curl|wget|httpclient)",
        -- 已知扫描器 User-Agent
        "(nikto|nmap|sqlmap|dirbuster|gobuster|wfuzz|hydra)",
        -- 可疑的 header 组合
        "(X-Forwarded-For:%s*%d+%.%d+%.%d+%.%d+,){3,}",
    }

    local patterns_to_check = pattern and {pattern} or cc_indicators

    for _, p in ipairs(patterns_to_check) do
        if _regex_match(ctx.user_agent, p) then
            return p
        end
    end

    return false
end

-- 路径遍历检测
function _check_path_traversal(ctx, pattern)
    local traversal_patterns = {
        "%.%.[/\\]", -- ../ 或 ..\
        "%.%.%/", -- %2e%2e/
        "%.%2[fF]", -- .%2f
        "%2[eE]%2[eE][/%5Cc]", -- %2e%2e/
        "/etc/(passwd|shadow|hosts)",
        "windows/system32",
        "boot%.ini",
        "web%.config",
    }

    local patterns_to_check = pattern and {pattern} or traversal_patterns

    for _, p in ipairs(patterns_to_check) do
        if _regex_match(ctx.uri, p) or _regex_match(ctx.body or "", p) then
            return p
        end
    end

    return false
end

-- 命令注入检测
function _check_command_injection(ctx, pattern)
    local cmd_patterns = {
        ";%s*(ls|cat|id|whoami|pwd|uname|wget|curl|nc|bash|sh|cmd|powershell)",
        "|%s*(ls|cat|id|whoami|pwd|uname|wget|curl|nc|bash|sh|cmd|powershell)",
        "`[^`]+`", -- 反引号执行
        "$%([^)]+)", -- $() 执行
        "%{%{.*}%}", -- 模板注入指示符
        "%${[^}]+}", -- 变量扩展
    }

    local patterns_to_check = pattern and {pattern} or cmd_patterns

    for _, p in ipairs(patterns_to_check) do
        if _regex_match(ctx.uri, p) or
           _regex_match(ctx.args, p) or
           (ctx.body and _regex_match(ctx.body, p)) then
            return p
        end
    end

    return false
end

-- 对任何字段进行通用正则匹配
function _regex_match_any(ctx, pattern)
    if _regex_match(ctx.uri, pattern) or
       _regex_match(ctx.args, pattern) or
       (ctx.body and _regex_match(ctx.body, pattern)) or
       _regex_match(ctx.cookie, pattern) then
        return pattern
    end

    return false
end

-- 带错误处理的安全正则匹配
function _regex_match(text, pattern)
    if not text or not pattern then
        return false
    end

    -- 使用 ngx.re.match 进行 PCRE 匹配以获得更好性能
    local matches, err = ngx.re.match(text, pattern, "ijo")

    if err then
        ngx.log(ngx.ERR, "正则错误 [", pattern, "]: ", err)
        return false
    end

    return matches ~= nil
end

-- 从 Redis 加载规则到缓存
function _load_rules()
    local keys, err = redis_pool.execute("KEYS", "waf:rules:*")

    if not keys or #keys == 0 then
        -- 无配置规则，使用空集
        _rules_cache = {}
        _last_update = ngx.now()
        return
    end

    -- 批量加载所有规则
    local commands = {}
    for _, key in ipairs(keys) do
        table.insert(commands, {"GET", key})
    end

    local results, pipe_err = redis_pool.pipeline(commands)

    if not results then
        ngx.log(ngx.ERR, "加载规则失败: ", pipe_err)
        return
    end

    -- 解析并缓存规则
    _rules_cache = {}

    for i, key in ipairs(keys) do
        if results[i] ~= ngx.null then
            local rule_data = cjson.decode(results[i])

            if rule_data and type(rule_data) == "table" then
                -- 确保必需字段存在
                rule_data.id = rule_data.id or string.sub(key, #"waf:rules:" + 1)
                rule_data.enabled = rule_data.enabled ~= false -- 默认为启用
                rule_data.priority = rule_data.priority or 100
                rule_data.action = rule_data.action or ACTIONS.DENY
                rule_data.severity = rule_data.severity or "medium"

                table.insert(_rules_cache, rule_data)
            end
        end
    end

    -- 按优先级排序（数字越小优先级越高）
    table.sort(_rules_cache, function(a, b)
        return (a.priority or 100) < (b.priority or 100)
    end)

    _last_update = ngx.now()

    ngx.log(ngx.DEBUG, "已加载并缓存 ", #_rules_cache, " 条 WAF 规则")
end

-- 强制从 Redis 重新加载规则
function _M.reload_rules()
    _rules_cache = {}
    _last_update = 0
    _load_rules()
end

-- 获取当前缓存的规则（用于调试/管理）
function _M.get_cached_rules()
    return _rules_cache
end

-- 导出常量供外部使用
_M.RULE_TYPES = RULE_TYPES
_M.ACTIONS = ACTIONS

return _M