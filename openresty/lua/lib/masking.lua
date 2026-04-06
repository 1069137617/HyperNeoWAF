-- 数据脱敏工具集
-- 在记录日志前对敏感信息进行脱敏处理

local _M = {}

-- 脱敏信用卡号: 4111111111111111 -> 4111****1111
function _M.mask_credit_card(number)
    if not number or type(number) ~= "string" then
        return ""
    end

    -- 去除空格和横杠
    local cleaned = string.gsub(number, "[%s%-]", "")

    if #cleaned < 8 then
        return string.rep("*", #cleaned)
    end

    local visible_start = math.min(4, #cleaned - 4)
    local visible_end = math.min(4, #cleaned - visible_start)

    return string.sub(cleaned, 1, visible_start) ..
           string.rep("*", #cleaned - visible_start - visible_end) ..
           string.sub(cleaned, -visible_end)
end

-- 脱敏身份证号（中国）: 保留前3位和后4位
function _M.mask_id_number(id)
    if not id or type(id) ~= "string" then
        return ""
    end

    local cleaned = string.gsub(id, "%s+", "")

    if #cleaned <= 7 then
        return string.rep("*", #cleaned)
    end

    return string.sub(cleaned, 1, 3) ..
           string.rep("*", #cleaned - 7) ..
           string.sub(cleaned, -4)
end

-- 脱敏手机号: 13812345678 -> 138****5678
function _M.mask_phone(phone)
    if not phone or type(phone) ~= "string" then
        return ""
    end

    local cleaned = string.gsub(phone, "[%s%-+]", "")

    if #cleaned <= 7 then
        return string.rep("*", #cleaned)
    end

    return string.sub(cleaned, 1, 3) ..
           string.rep("*", #cleaned - 7) ..
           string.sub(cleaned, -4)
end

-- 脱敏邮箱: user@example.com -> u***@example.com
function _M.mask_email(email)
    if not email or type(email) ~= "string" then
        return ""
    end

    local _, _, username, domain = string.find(email, "^([^@]+)@(.+)$")

    if not username or not domain then
        return "***@***.***"
    end

    if #username <= 1 then
        return "*@" .. domain
    end

    return string.sub(username, 1, 1) ..
           string.rep("*", #username - 1) ..
           "@" .. domain
end

-- 脱敏密码字段（始终返回固定遮罩）
function _M.mask_password(value)
    -- 密码永不记录日志，始终返回固定遮罩
    return "[REDACTED]"
end

-- 根据字段名模式进行通用字段脱敏
function _M.mask_field(field_name, value)
    if type(value) ~= "string" then
        return tostring(value)
    end

    local lower_name = string.lower(field_name)

    -- 信用卡模式
    if string.match(lower_name, "card") or
       string.match(lower_name, "credit") or
       string.match(lower_name, "cc[_%-]?num") then
        return _M.mask_credit_card(value)
    end

    -- 身份证模式
    if string.match(lower_name, "id[_%-]?card") or
       string.match(lower_name, "ssn") or
       string.match(lower_name, "identity") then
        return _M.mask_id_number(value)
    end

    -- 手机号模式
    if string.match(lower_name, "phone") or
       string.match(lower_name, "mobile") or
       string.match(lower_name, "tel") then
        return _M.mask_phone(value)
    end

    -- 邮箱模式
    if string.match(lower_name, "email") or
       string.match(lower_name, "mail") then
        return _M.mask_email(value)
    end

    -- 密码模式 - 始终遮罩
    if string.match(lower_name, "pass") or
       string.match(lower_name, "pwd") or
       string.match(lower_name, "secret") or
       string.match(lower_name, "token") or
       string.match(lower_name, "key") then
        return _M.mask_password(value)
    end

    -- 默认：原样返回（但过长时截断）
    if #value > 100 then
        return string.sub(value, 1, 100) .. "...[TRUNCATED]"
    end

    return value
end

-- 对表中所有敏感字段进行脱敏
function _M.mask_table(data)
    if type(data) ~= "table" then
        return data
    end

    local masked = {}

    for k, v in pairs(data) do
        masked[k] = _M.mask_field(k, v)
    end

    return masked
end

return _M