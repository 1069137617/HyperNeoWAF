# Tasks - WAF Project Initialization

## Phase 1: 项目基础设施搭建 ✅
- [x] Task 1.1: 创建项目根目录结构
  - [x] 创建 openresty/ 目录及子目录 (conf, lua/init, lua/access, lua/filter, lua/log, lib, lualib)
  - [x] 创建 backend/ 目录及子目录 (cmd, internal/api, middleware, model, service, repository, embed, pkg, configs, web)
  - [x] 创建 frontend/ 目录及子目录 (src/views, src/components, src/stores, src/api, src/utils, styles, i18n/locales, public)
  - [x] 创建 scripts/, docs/ 目录
  - [x] 创建 .gitignore 文件

- [x] Task 1.2: 初始化 OpenResty 配置
  - [x] 创建 nginx.conf 主配置文件 (含 Lua 集成、upstream、WAF 处理阶段)
  - [x] 配置 Lua 路径和 package.path
  - [x] 定义 upstream (backend_server) 和 server block
  - [x] 配置各阶段 Lua 处理指令 (init_by_lua_block, access_by_lua_file, log_by_lua_file)
  - [x] 创建 mime.types 配置
  - [x] 创建 waf_access.lua 和 waf_logger.lua 入口文件

- [x] Task 1.3: 初始化 Go 后端项目 (含嵌入式前端服务)
  - [x] 创建 go.mod 文件，定义模块路径和依赖
  - [x] 创建 main.go 入口文件 (含静态文件服务 + SPA Fallback + API 路由)
  - [x] 创建 config.go 配置加载器 (支持 YAML + 环境变量覆盖)
  - [x] 创建 handlers.go 占位符 handler 函数 (18 个 API 端点)
  - [x] 创建 config.yaml 配置文件结构 (server, database, redis, jwt, logging)
  - [x] 创建 internal/embed/embed.go (//go:embed all:web)
  - [x] 实现 Go 静态文件服务器 (使用 //go:embed 嵌入 dist/)
  - [x] 配置 SPA Fallback 中间件 (非 API 路径返回 index.html)
  - [x] 创建 backend/web/ 目录作为前端构建输出目标

- [x] Task 1.4: 初始化 Vue 3 前端项目
  - [x] 创建 package.json 并配置依赖 (vue, naive-ui, pinia, vue-router, vue-i18n, axios, @vicons/ionicons5)
  - [x] 创建 vite.config.ts 配置文件 (输出到 ../backend/web/, dev proxy to :8080)
  - [x] 配置 Vite 输出目录为 ../backend/web/ (Go embed 源)
  - [x] 创建 tsconfig.json TypeScript 配置 (strict mode, path aliases)
  - [x] 创建 tsconfig.node.json (Vite 配置专用)
  - [x] 创建 index.html 入口文件
  - [x] 创建 src/main.ts (注册 Pinia, Router, i18n, Naive UI)
  - [x] 创建 src/App.vue (NConfigProvider 根组件)
  - [x] 配置 Vue Router 使用 History 模式 (base: '/', 路由守卫)
  - [x] 创建 stores/auth.ts (Pinia 认证状态管理)
  - [x] 创建 api/request.ts (Axios 实例 + JWT 拦截器)
  - [x] 创建 i18n/index.ts + locales/en-US.json + zh-CN.json (国际化)
  - [x] 创建 views/Login.vue (登录页面，含表单验证)
  - [x] 创建 views/DashboardView.vue (仪表盘占位)
  - [x] 创建 views/RulesView.vue (规则管理占位)
  - [x] 创建 views/LogsView.vue (日志审计占位)
  - [x] 创建 views/IPListView.vue (IP 管理占位)
  - [x] 创建 styles/main.css (全局样式 + CSS 变量)

## Phase 2: OpenResty/Lua 核心实现 ✅
- [x] Task 2.1: 实现 Redis 连接池管理
  - [x] 编写 lua/lib/redis_pool.lua - 连接池初始化和管理
  - [x] 实现 get_connection() 和 release_connection() 方法
  - [x] 配置 keepalive 参数 (timeout=10000ms, pool_size=100)
  - [x] 实现 execute() 和 pipeline() 封装方法
  - [x] 实现健康检查 health_check()

- [x] Task 2.1-bonus: 创建配置加载器
  - [x] 编写 lua/lib/config.lua - 从 Redis 加载配置
  - [x] 支持缓存和 TTL 自动刷新
  - [x] 支持 get/set/refresh 操作

- [x] Task 2.2: 实现 IP 黑名单检查
  - [x] 编写 lua/access/ip_check.lua
  - [x] 从 Redis waf:blacklist/waf:whitelist 读取 IP 列表
  - [x] 实现 IPv4 精确匹配 + CIDR 范围匹配
  - [x] 白名单优先级高于黑名单
  - [x] 本地缓存优化 (TTL=30s)
  - [x] 提供 add_to_blacklist/remove_from_blacklist API

- [x] Task 2.3: 实现速率限制功能
  - [x] 编写 lua/access/rate_limit.lua
  - [x] 使用 Redis Lua 脚本实现原子性计数 (EVALSHA)
  - [x] 支持按 IP 维度限流 (默认 60 req/min)
  - [x] 支持按 URL 维度限流 (默认 120 req/min)
  - [x] 支持按 User-Agent 维度限流 (检测机器人, 200 req/min)
  - [x] 综合检查函数 check_comprehensive()
  - [x] 设置 X-RateLimit-* 响应头
  - [x] 超限时返回 429 Too Many Requests

- [x] Task 2.4: 实现基础规则匹配引擎
  - [x] 编写 lua/filter/rule_engine.lua
  - [x] 从 Redis waf:* 加载规则并缓存 (TTL=10s)
  - [x] SQL 注入检测 (20+ 种攻击模式: UNION SELECT, DROP TABLE, SLEEP(), etc.)
  - [x] XSS 检测 (<script>, javascript:, on* handlers, eval(), etc.)
  - [x] CC 攻击检测 (扫描器 UA 识别: sqlmap, nikto, nmap, etc.)
  - [x] 路径遍历检测 (../, %2e%2e/, /etc/passwd, etc.)
  - [x] 命令注入检测 (; | ` $() 等)
  - [x] 使用 ngx.re.match 进行高性能正则匹配
  - [x] 规则优先级排序 (priority 字段)
  - [x] 支持 deny/log_only/allow 三种动作

- [x] Task 2.5: 实现日志采集与发送 + 数据脱敏
  - [x] 编写 lua/lib/masking.lua - 数据脱敏工具库
    - [x] mask_credit_card(): 4111111111111111 -> 4111****1111
    - [x] mask_id_number(): 身份证号保留前3后4位
    - [x] mask_phone(): 手机号保留前3后4位
    - [x] mask_email(): user@example.com -> u***@example.com
    - [x] mask_password(): 密码字段永远返回 [REDACTED]
    - [x] mask_field(): 根据字段名自动识别类型脱敏
    - [x] mask_table(): 批量脱敏整个表数据
  - [x] 编写 lua/log/logger.lua - 异步日志发送器
    - [x] 收集请求数据 (IP, URL, Method, Status, Headers, Body, WAF action, etc.)
    - [x] 所有敏感字段自动脱敏处理
    - [x] 使用 ngx.timer.at 异步发送 (非阻塞)
    - [x] 通过 HTTP POST 发送到 Go 后端 /api/v1/logs/receive
    - [x] 缓冲区机制 (buffer_size=100, flush_interval=5s)
    - [x] 本地文件 fallback (/var/log/waf/YYYY-MM-DD_fallback.log)
    - [x] 使用 resty.http 库进行 HTTP 通信

- [x] Task 2.6: 更新前端组件 (移除 emoji, 使用 SVG 图标)
  - [x] 更新 DashboardView.vue:
    - [x] Total Requests: SVG 图表图标 (绿色 #18a058)
    - [x] Blocked Requests: SVG 阻止图标 (红色 #d03050)
    - [x] QPS: SVG 性能图标 (橙色 #f0a020)
    - [x] Block Rate: SVG 趋势图标 (蓝色 #4098fc)
    - [x] 卡片标题使用 @vicons/ionicons5 图标组件
    - [x] 空状态使用自定义 SVG 占位符
    - [x] 添加 hover 动画效果

## Phase 3: Go 后端 API 服务 ✅
- [x] Task 3.1: 实现数据模型层
  - [x] 创建 User 模型 (ID, Username, PasswordHash, Role, IsActive, LastLoginAt)
    - [x] 定义 UserRoles 常量 (Admin, Editor, Viewer)
    - [x] 软删除支持 (gorm.DeletedAt)
  - [x] 创建 Rule 模型 (ID, Name, Type, Pattern, Action, Enabled, Priority, Severity, Version)
    - [x] 定义 RuleTypes (8种: SQL Injection, XSS, CC Attack 等)
    - [x] 定义 RuleActions (Deny, Allow, LogOnly)
    - [x] 定义 RuleSeverities (Low, Medium, High, Critical)
  - [x] 创建 SecurityLog 模型 (完整字段: Timestamp, ClientIP, Method, URI, HeadersJSON, WAFAction, WAFRule, RateLimit info, Performance metrics)
    - [x] 支持 JSONB 字段存储 Headers 和 Body
    - [x] 定义 WAFActions 常量
  - [x] 创建 IPListEntry 模型 (IP, Type, Reason, ExpiresAt, Source, IsActive)
    - [x] 定义 IPListTypes (Blacklist, Whitelist)
    - [x] 定义 IPListSources (Manual, AutoBlock, API)
    - [x] IsExpired() 方法检查过期状态
  - [x] 创建 SystemConfig 模型 (Key, Value, ValueType, Group, IsPublic)
    - [x] 定义 ConfigGroups 和 ValueTypes 常量

- [x] Task 3.2: 实现数据库连接与迁移
  - [x] 配置 PostgreSQL/GORM 连接 (database/repository/database.go)
    - [x] DSN 构建 (host, port, user, password, dbname, sslmode)
    - [x] 连接池配置 (MaxOpenConns, MaxIdleConns, ConnMaxLifetime)
  - [x] 编写 AutoMigrate 初始化表结构 (5个模型自动迁移)
  - [x] 实现 HealthCheck() 和 Close() 方法
  - [x] 全局 DB 实例导出

- [x] Task 3.3: 实现认证中间件 + 认证服务
  - [x] 编写 JWT Token 生成和验证逻辑 (middleware/auth.go)
    - [x] JWTClaims 结构体 (UserID, Username, Role + RegisteredClaims)
    - [x] GenerateTokenPair() - Access Token (24h) + Refresh Token (7d)
    - [x] ValidateToken() - 解析并验证 Token 签名和过期时间
    - [x] AuthMiddleware() - Gin 中间件，提取 Bearer Token 并验证
    - [x] RoleMiddleware() - 角色权限检查中间件
  - [x] 实现认证服务 (service/auth_service.go)
    - [x] Authenticate() - 验证用户名密码 (bcrypt.CompareHashAndPassword)
    - [x] CreateUser() - 创建用户 (bcrypt.GenerateFromPassword, cost=12)
    - [x] ChangePassword() - 修改密码
    - [x] EnsureDefaultAdmin() - 确保默认管理员账户存在
  - [x] 实现 API 处理器 (api/auth_handler.go)
    - [x] POST /api/v1/auth/login - 登录返回 JWT Token 对
    - [x] POST /api/v1/auth/refresh - 刷新 Access Token
    - [x] GET /api/v1/auth/profile - 获取当前用户信息
    - [x] PUT /api/v1/auth/password - 修改密码

- [x] Task 3.4: 实现规则管理 API (完整 CRUD + Redis 同步)
  - [x] 编写规则服务层 (service/rule_service.go)
    - [x] CreateRule() - 创建规则并同步到 Redis
    - [x] GetRuleByID() - 按 ID 获取规则
    - [x] ListRules() - 分页列表 (支持 type/enabled/action/search 过滤)
    - [x] UpdateRule() - 更新规则 (版本号自增) + Redis 同步
    - [x] DeleteRule() - 软删除 + Redis 清理
    - [x] SyncAllRulesToRedis() - 批量同步所有启用规则到 Redis
  - [x] 编写 API 处理器 (api/rule_handler.go)
    - [x] GET /api/v1/rules - 列表查询 (分页+筛选)
    - [x] POST /api/v1/rules - 创建规则 (参数验证)
    - [x] GET /api/v1/rules/:id - 获取单个规则
    - [x] PUT /api/v1/rules/:id - 更新规则
    - [x] DELETE /api/v1/rules/:id - 删除规则
    - [x] PUT /api/v1/rules/sync - 手动触发全量同步到 Redis

- [x] Task 3.5: 实现日志接收与查询 API (含二次脱敏)
  - [x] 编写日志服务层 (service/log_service.go)
    - [x] ReceiveLogs() - 接收 OpenResty 批量日志 (批量处理 + batch ID)
    - [x] processRawLog() - 原始日志转换 (二次脱敏处理)
    - [x] ListLogs() - 多维度筛选分页查询 (时间/IP/方法/动作/规则/搜索)
    - [x] ExportLogs() - 导出为 CSV 或 JSON 格式
    - [x] GetLogStats() - 聚合统计 (总请求/拦截数/拦截率/Top URL/攻击分布)
  - [x] 编写脱敏服务 (service/masking_service.go)
    - [x] MaskField() - 根据字段名自动识别类型脱敏
    - [x] MaskTable() - 递归脱敏 map/slice 结构
    - [x] 信用卡/身份证/手机/邮箱/密码 五种脱敏算法
  - [x] 编写 API 处理器 (api/log_handler.go)
    - [x] POST /api/v1/logs/receive - 接收 OpenResty 日志
    - [x] GET /api/v1/logs - 日志列表 (多条件筛选)
    - [x] GET /api/v1/logs/:id - 日志详情
    - [x] GET /api/v1/logs/export - 日志导出 (CSV/JSON)
    - [x] GET /api/v1/logs/stats - 统计数据

- [x] Task 3.6: 实现 IP 黑白名单 API + Redis 同步
  - [x] 编写 IP 管理服务 (service/ip_list_service.go)
    - [x] AddIP() - 添加 IP 到黑/白名单 + Redis 同步
    - [x] ListIPs() - 分页查询 (可按类型过滤)
    - [x] GetIPByID() - 获取单个条目
    - [x] DeleteIP() - 删除条目 + Redis 清理
    - [x] SyncAllIPsToRedis() - 批量同步到 Redis (waf:blacklist:{ip}, waf:whitelist:{ip})
    - [x] 支持过期时间 (TTL 自动设置)
  - [x] 编写 API 处理器 (api/ip_list_handler.go)
    - [x] GET /api/v1/ip-list - 列表查询
    - [x] POST /api/v1/ip-list - 添加单条 IP
    - [x] POST /api/v1/ip-list/batch-import - 批量导入 (最多1000条)
    - [x] GET /api/v1/ip-list/:id - 获取详情
    - [x] DELETE /api/v1/ip-list/:id - 删除条目
    - [x] PUT /api/v1/ip-list/sync - 手动触发全量同步

- [x] Task 3.7: 实现 Dashboard 统计 API
  - [x] 编写 Dashboard 服务 (service/dashboard_service.go)
    - [x] GetDashboardStats() - 总体统计 (请求数/拦截数/QPS/活跃规则/黑白名单数)
    - [x] GetTrends() - 趋势数据 (1h/6h/24h/7d 可选, 请求数/拦截数/QPS 曲线)
    - [x] GetRecentEvents() - 最近安全事件 (可配置数量, 默认20条)
    - [x] GetTopAttacks() - Top 攻击类型排行 (按频率排序, 含百分比)
  - [x] 编写 API 处理器 (api/dashboard_handler.go)
    - [x] GET /api/v1/dashboard/stats - 总体统计数据
    - [x] GET /api/v1/dashboard/trends - 趋势数据 (支持 range 参数)
    - [x] GET /api/v1/dashboard/recent-events - 最近事件
    - [x] GET /api/v1/dashboard/top-attacks - Top 攻击排行
    - [x] GET /api/v1/dashboard/qps - 轻量级 QPS 轮询接口

- [x] Task 3.8: 重构 main.go 使用分层架构
  - [x] 引入 database/middleware/service/api/repository 包
  - [x] 初始化数据库连接池
  - [x] 初始化 Redis 客户端
  - [x] 初始化 JWT 认证中间件
  - [x] 注入所有 Service 和 Handler
  - [x] 注册完整的路由组 (auth/rules/logs/ip-list/dashboard)
  - [x] 保持静态文件服务和 SPA Fallback 功能

## Phase 4: 前端管理面板 ✅
- [x] Task 4.1: 实现前端基础架构
  - [x] 配置 Vue Router 路由定义 (History 模式 + 路由守卫)
  - [x] 配置 Pinia Store (auth store 完整实现: login/logout/refreshToken)
  - [x] 配置 vue-i18n 国际化 (en-US, zh-CN 完整翻译)
  - [x] 创建 Axios 实例配置 (baseURL, JWT 拦截器, 自动刷新队列)
  - [x] 实现布局组件 AppLayout.vue (Sidebar 导航 + Header 面包屑 + 用户菜单)

- [x] Task 4.2: 实现登录与认证页面
  - [x] 创建 Login.vue 登录页面 (背景装饰 + 表单验证)
  - [x] 实现登录表单验证 (用户名/密码必填, 最小长度)
  - [x] 存储 JWT Token 到 localStorage (access_token + refresh_token)
  - [x] 实现路由守卫检查认证状态 (beforeEach 拦截)
  - [x] 创建 Token 自动刷新机制 (401 拦截 + refresh queue)

- [x] Task 4.3: 实现 Dashboard 监控大屏
  - [x] 创建 DashboardView.vue 主页面 (8 个统计卡片)
  - [x] 统计卡片: Total Requests / Blocked / QPS / Block Rate / Active Rules / Blacklisted IPs / Whitelisted IPs / Rate Limited
  - [x] NTimeline 展示最近安全事件 (时间线样式)
  - [x] NProgress 进度条展示 Top 攻击类型排行
  - [x] 轮询实现数据实时更新 (每 5 秒自动刷新)

- [x] Task 4.4: 实现规则管理页面
  - [x] 创建 RulesView.vue 规则列表页 (NDataTable 表格)
  - [x] 搜索框 + 类型过滤下拉框
  - [x] 规则创建/编辑弹窗 NModal (完整表单: name/description/type/pattern/action/severity/priority)
  - [x] 规则启用/禁用切换 NSwitch (即时生效)
  - [x] 删除确认对话框 NPopconfirm
  - [x] Sync to Redis 按钮 (手动触发同步)
  - [x] 颜色编码标签 (Type/Action/Severity)

- [x] Task 4.5: 实现日志审计中心
  - [x] 创建 LogsView.vue 日志查询页 (6 维度筛选器)
  - [x] 筛选器: 日期范围选择器 / Client IP / HTTP Method / WAF Action / 搜索文本 / 重置按钮
  - [x] 分页数据表格 (格式化显示各字段)
  - [x] 日志详情抽屉 NDrawer (NDescriptions 展示完整信息)
  - [x] 日志导出功能 (CSV / JSON 格式 Blob 下载)
  - [x] 大数据量分页加载优化

- [x] Task 4.6: 实现 IP 管理页面
  - [x] 创建 IPListView.vue (NTabs 黑白名单标签页切换)
  - [x] Add IP 弹窗 (Type 单选组 / IP 输入 / Reason / Expiry DatetimePicker)
  - [x] Batch Import 弹窗 (Textarea 批量导入, 一行一个 IP)
  - [x] Sync to Redis 按钮 (手动触发全量同步)
  - [x] 等宽字体展示 IP 地址
  - [x] 删除确认对话框

## Phase 5: 安全加固与集成测试
- [ ] Task 5.1: 实现数据脱敏工具库
  - [ ] Go: internal/pkg/masking/masking.go - 脱敏函数
  - [ ] Lua: lua/lib/masking.lua - 脱敏函数
  - [ ] 覆盖所有 PII 类型 (信用卡、身份证、手机、邮箱)

- [ ] Task 5.2: Docker 容器化部署 (单端口架构)
  - [ ] 编写 Dockerfile for OpenResty
  - [ ] 编写 Dockerfile for Go Backend (多阶段构建：前端构建 + Go 编译)
    - 阶段 1: node:alpine - npm install && npm run build (生成 dist/)
    - 阶段 2: golang:alpine - CGO_ENABLED=0 go build (嵌入 dist/)
    - 最终镜像包含完整二进制文件
  - [ ] 编写 docker-compose.yml 编排所有服务
    - openresty service (WAF 网关)
    - backend service (API + 前端静态文件, 单端口暴露)
    - redis service (状态存储)
  - [ ] 配置 Redis 服务

- [ ] Task 5.3: 编写单元测试
  - [ ] Go: 规则匹配逻辑测试
  - [ ] Go: 脱敏函数测试
  - [ ] Go: API handler 测试
  - [ ] Lua: 速率限制逻辑测试

- [ ] Task 5.4: 性能基准测试
  - [ ] 使用 wrk/ab 进行压力测试
  - [ ] 验证 QPS 和延迟指标达标
  - [ ] 识别并优化瓶颈

## Task Dependencies
- [Task 1.2] depends on [Task 1.1]
- [Task 1.3] depends on [Task 1.1]
- [Task 1.4] depends on [Task 1.1]
- [Task 2.1] depends on [Task 1.2]
- [Task 2.2] depends on [Task 2.1]
- [Task 2.3] depends on [Task 2.1]
- [Task 2.4] depends on [Task 2.1]
- [Task 2.5] depends on [Task 2.1]
- [Task 3.2] depends on [Task 3.1]
- [Task 3.3] depends on [Task 3.2]
- [Task 3.4] depends on [Task 3.2]
- [Task 3.5] depends on [Task 3.2]
- [Task 3.6] depends on [Task 3.2]
- [Task 3.7] depends on [Task 3.5]
- [Task 4.1] depends on [Task 1.4]
- [Task 4.2] depends on [Task 4.1]
- [Task 4.3] depends on [Task 4.1, Task 3.7]
- [Task 4.4] depends on [Task 4.1, Task 3.4]
- [Task 4.5] depends on [Task 4.1, Task 3.5]
- [Task 4.6] depends on [Task 4.1, Task 3.6]
- [Task 5.1] depends on [Task 2.5, Task 3.5]
- [Task 5.2] depends on [Phase 2, Phase 3, Phase 4]
- [Task 5.3] depends on [Phase 2, Phase 3]
- [Task 5.4] depends on [Phase 2, Phase 3, Phase 4, Task 5.2]
