# Web Application Firewall (WAF) Project Spec

## Why
构建一个高性能、高安全性的 Web 应用防火墙系统，用于保护 Web 应用免受常见攻击（SQL 注入、XSS、CC 攻击等），同时满足严格的隐私保护要求。

## What Changes
- **新建项目**: 从零开始构建完整的 WAF 系统
- **核心组件**:
  - OpenResty (Nginx + LuaJIT) 网关层
  - Go 后端管理服务
  - Vue 3 + Naive UI 前端管理面板
  - Redis 状态共享层
- **安全特性**: 数据脱敏、速率限制、IP 黑白名单、规则引擎
- **隐私保护**: PII 脱敏、最小化日志收集

## Impact
- Affected specs: N/A (新项目)
- Affected code: 全部代码库

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│              Single Port Architecture                        │
│                                                              │
│  ┌──────────────────────────────────────────────────┐      │
│  │              Go Backend (:8080)                   │      │
│  │  ┌─────────────────┐  ┌────────────────────────┐ │      │
│  │  │ Static File     │  │ RESTful API            │ │      │
│  │  │ Server (embed)  │  │ /api/v1/*              │ │      │
│  │  │                 │  ├────────────────────────┤ │      │
│  │  │ Vue 3 + Naive UI│  │ Rule Mgr │ Auth │ Log  │ │      │
│  │  │ (dist/)         │  │ Config   │ Sync │ Dash │ │      │
│  │  └─────────────────┘  └───────────┬────────────┘ │      │
│  │                                  │               │      │
│  │                       ┌──────────▼────────────┐  │      │
│  │                       │    PostgreSQL         │  │      │
│  │                       └───────────────────────┘  │      │
│  └───────────────────────────┬──────────────────────┘      │
│                              │ HTTP/TCP Logs                │
│                              ▼                              │
│  ┌──────────────────────────────────────────────────┐      │
│  │           OpenResty (Nginx + LuaJIT)             │      │
│  │  ┌──────────────────────────────────────────┐   │      │
│  │  │          Lua Request Processing           │   │      │
│  │  │  init → access → body_filter → log        │   │      │
│  │  └──────────────────────┬───────────────────┘   │      │
│  │                          │                        │      │
│  │  ┌──────────────────────▼───────────────────┐   │      │
│  │  │                  Redis                    │   │      │
│  │  │  waf:* (ratelimit, blacklist, rules)     │   │      │
│  │  └──────────────────────────────────────────┘   │      │
│  └──────────────────────────────────────────────────┘      │
│                                                              │
│  Deployment: 3 Containers (OpenResty, Go+Frontend, Redis)   │
│  Admin Access: Single Port via Go Backend                    │
└─────────────────────────────────────────────────────────────┘
```

## ADDED Requirements

### Requirement: Project Structure Initialization
系统 SHALL 提供标准化的项目目录结构，包含以下模块：

```
waf-project/
├── openresty/                 # OpenResty/Lua 网关层
│   ├── conf/                  # Nginx 配置文件
│   │   └── nginx.conf
│   ├── lua/                   # Lua 脚本
│   │   ├── init/             # 初始化阶段
│   │   ├── access/           # 访问控制阶段
│   │   ├── filter/           # 过滤器
│   │   ├── log/              # 日志处理
│   │   └── lib/              # 工具库
│   └── lualib/               # 第三方 Lua 库
├── backend/                  # Go 后端服务 (含嵌入式前端)
│   ├── cmd/                  # 入口文件
│   ├── internal/             # 内部包
│   │   ├── api/             # API 处理器
│   │   ├── middleware/       # 中间件
│   │   ├── model/           # 数据模型
│   │   ├── service/         # 业务逻辑
│   │   ├── repository/      # 数据访问
│   │   └── embed/           # 嵌入式静态文件 (dist/)
│   ├── pkg/                 # 公共包
│   ├── configs/             # 配置文件
│   └── web/                 # 前端构建产物 (gitignored, 由 frontend/ 构建生成)
├── frontend/                 # Vue 3 前端源码 (开发用)
│   ├── src/
│   │   ├── views/           # 页面组件
│   │   ├── components/      # 公共组件
│   │   ├── stores/          # 状态管理
│   │   ├── api/             # API 调用
│   │   └── utils/           # 工具函数
│   └── package.json
├── scripts/                  # 部署脚本
├── docs/                     # 文档
└── docker-compose.yml        # 容器编排 (3 services: openresty, backend, redis)
```

#### Scenario: Project scaffolding success case
- **WHEN** 开发者执行项目初始化命令
- **THEN** 所有必要的目录结构和基础配置文件被正确创建
- **THEN** 各模块可以独立运行和测试

### Requirement: OpenResty Core Engine
OpenResty 网关层 SHALL 实现以下功能：

1. **请求生命周期管理**
   - `init_by_lua_block`: 初始化 Redis 连接池、加载全局配置
   - `access_by_lua_block`: IP 检查、速率限制、签名匹配
   - `body_filter_by_lua_block`: 响应体过滤（可选）
   - `log_by_lua_block`: 异步日志发送

2. **Redis 集成**
   - 使用 `lua-resty-redis` 库
   - 连接池配置：keepalive_timeout=10000ms, pool_size=100
   - 键名前缀规范：`waf:{module}:{key}`

3. **性能约束**
   - 单请求处理延迟 < 5ms (P99)
   - 支持 10K+ QPS
   - 非阻塞 I/O 操作

#### Scenario: Request interception success case
- **WHEN** 恶意请求到达网关
- **THEN** 系统在 access 阶段识别威胁类型
- **THEN** 根据规则返回适当的 HTTP 状态码 (403/429)
- **THEN** 异步记录安全事件日志

### Requirement: Go Backend API Service
Go 后端服务 SHALL 提供：

1. **RESTful API 端点**
   - `/api/v1/rules` - 规则 CRUD
   - `/api/v1/logs` - 日志查询与导出
   - `/api/v1/auth` - 认证接口
   - `/api/v1/config` - 系统配置
   - `/api/v1/dashboard` - 监控数据
   - `/api/v1/ip-list` - IP 黑白名单管理

2. **认证机制**
   - JWT Bearer Token 认证
   - Token 有效期：24 小时
   - Refresh Token：7 天
   - 密码存储：bcrypt (cost >= 12)

3. **规则同步**
   - 规则变更时实时更新 Redis 缓存
   - 支持版本控制和回滚

#### Scenario: API authentication success case
- **WHEN** 管理员使用有效凭据登录
- **THEN** 返回 JWT Access Token 和 Refresh Token
- **THEN** Token 包含角色信息和过期时间
- **THEN** 后续请求使用 Token 成功认证

### Requirement: Frontend Dashboard
前端管理面板 SHALL 实现：

1. **技术栈**
   - Vue 3 Composition API (`<script setup lang="ts">`)
   - Naive UI 组件库
   - Vite 构建工具
   - Pinia 状态管理
   - Vue Router 4 (使用 History 模式)

2. **部署架构：Go 嵌入式静态文件服务**
   - 开发环境：Vite Dev Server (支持 HMR)
   - 生产环境：`npm run build` 生成 `dist/` 目录
   - Go 后端使用 `//go:embed` 将 `dist/` 嵌入二进制文件
   - Go 使用 `http.FileServer` 提供静态文件服务
   - SPA Fallback：所有非 `/api/*` 和非静态资源路径返回 `index.html`
   - **单端口访问**：管理面板和 API 共享同一端口（默认 :8080）

3. **核心页面**
   - Dashboard（实时监控大屏）
   - Rules Management（规则管理）
   - Log Audit Center（日志审计）
   - IP List Manager（IP 管理）
   - System Settings（系统设置）

4. **国际化支持**
   - 默认语言：英文
   - 支持中文切换
   - 使用 vue-i18n

#### Scenario: Dashboard rendering success case
- **WHEN** 管理员通过浏览器访问 Go Backend 端口
- **THEN** Go 返回嵌入的 Vue 3 应用 (index.html)
- **THEN** 显示实时 QPS 统计图表
- **THEN** 显示拦截率趋势图
- **THEN** 显示最近攻击事件列表
- **THEN** 数据每 5 秒自动刷新

#### Scenario: Static file serving with SPA fallback
- **WHEN** 用户直接访问 `/dashboard` 或刷新页面
- **THEN** Go 正确返回 index.html (SPA fallback)
- **THEN** Vue Router 处理客户端路由
- **WHEN** 用户请求 `/api/v1/dashboard/stats`
- **THEN** 请求被路由到 API handler，而非静态文件

### Requirement: Data Privacy & Security
系统 SHALL 实现严格的数据保护和安全措施：

1. **数据脱敏规则**
   - 信用卡号：`4111111111111111` → `4111****1111`
   - 身份证号：保留前 3 后 4 位
   - 手机号：保留前 3 后 4 位
   - Email：`user@example.com` → `u***@example.com`
   - 密码字段：永远不记录明文

2. **Redis 安全**
   - 键名统一前缀避免冲突
   - 敏感数据加密存储（可选）
   - 设置合理的 TTL

3. **安全编码标准**
   - Go：参数化 SQL 查询，禁止字符串拼接
   - Vue：使用 v-text 或 DOMPurify，禁用 v-html
   - Lua：禁止使用 loadstring/loadfile 执行动态代码

#### Scenario: Sensitive data masking success case
- **WHEN** 日志中包含信用卡号等敏感信息
- **THEN** 自动应用脱敏规则
- **THEN** 日志输出仅显示掩码后的数据
- **THEN** 原始数据不可从日志恢复

## MODIFIED Requirements
N/A (新项目)

## REMOVED Requirements
N/A (新项目)

## Technical Constraints

### Performance Targets
| 指标 | 目标值 |
|------|--------|
| 网关延迟 (P50) | < 2ms |
| 网关延迟 (P99) | < 5ms |
| 吞吐量 | > 10,000 QPS |
| 并发连接数 | > 50,000 |
| 规则匹配时间 | < 0.1ms/rule |

### Security Standards
- OWASP Top 10 防护覆盖
- GDPR 合规的数据处理
- 定期安全审计日志
- 最小权限原则

### Code Quality
- Go: gofmt, golint, 单元测试覆盖率 > 80%
- Lua: luacheck 静态分析
- Vue: ESLint + Prettier, TypeScript strict mode
