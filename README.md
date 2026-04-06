# Web Application Firewall (WAF) - 应用防火墙

一个高性能、高安全性的 Web 应用防火墙系统，用于保护 Web 应用免受常见攻击（SQL 注入、XSS、CC 攻击等），同时满足严格的隐私保护要求。

## 项目架构

本项目采用**单端口架构**设计，通过 OpenResty 网关层和 Go 后端服务的组合，提供统一的流量管理和安全防护能力。

### 核心组件

- **OpenResty (Nginx + LuaJIT)**: 网关层，负责流量过滤、速率限制、规则引擎执行
- **Go Backend**: 后端管理服务，提供 RESTful API 和前端静态文件服务
- **Vue 3 + Naive UI**: 前端管理面板，提供可视化的配置和监控界面
- **Redis**: 状态共享层，用于缓存规则、会话管理和速率限制计数
- **PostgreSQL**: 持久化存储，存储配置、日志和用户数据

### 架构图

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

## 目录结构

```
waf-project/
├── openresty/                 # OpenResty/Lua 网关层
│   ├── conf/                  # Nginx 配置文件
│   │   └── nginx.conf
│   ├── lua/                   # Lua 脚本
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
│   │   └── embed/           # 嵌入式静态文件
│   ├── pkg/                 # 公共包
│   ├── configs/             # 配置文件
│   └── web/                 # 前端构建产物
├── frontend/                 # Vue 3 前端源码
│   ├── src/
│   │   ├── views/           # 页面组件
│   │   ├── components/      # 公共组件
│   │   ├── stores/          # 状态管理
│   │   ├── api/             # API 调用
│   │   └── utils/           # 工具函数
│   └── package.json
├── docs/                     # 文档
└── docker-compose.yml        # 容器编排
```

## 核心功能

### 1. 安全防护

- **SQL 注入检测**: 识别并阻断 SQL 注入攻击
- **XSS 攻击防护**: 检测和过滤跨站脚本攻击
- **CC 攻击防护**: 基于速率限制的 CC 攻击防护
- **命令注入检测**: 防止系统命令注入攻击
- **0day 攻击检测**: 基于行为分析的未知攻击检测

### 2. 访问控制

- **IP 黑白名单**: 支持 IP 地址的黑名单和白名单管理
- **速率限制**: 基于 IP 和请求频率的速率限制
- **规则引擎**: 可配置的请求过滤规则引擎

### 3. 数据隐私

- **PII 脱敏**: 自动检测和脱敏个人敏感信息
- **最小化日志**: 仅收集必要的日志信息
- **安全日志**: 记录安全事件，支持审计

### 4. 管理功能

- **仪表盘**: 实时展示系统状态和攻击统计
- **规则管理**: 可视化的规则配置和管理
- **日志查询**: 支持安全日志的查询和分析
- **系统配置**: 系统参数的可视化管理

## 技术栈

### 后端

- **语言**: Go 1.x
- **框架**: Gin (Web 框架)
- **数据库**: PostgreSQL (持久化存储)
- **缓存**: Redis (缓存和会话管理)
- **认证**: JWT (双令牌机制)

### 网关层

- **核心**: OpenResty (Nginx + LuaJIT)
- **脚本**: Lua (请求处理和规则执行)
- **共享内存**: Nginx shared dict (高性能缓存)

### 前端

- **框架**: Vue 3 + TypeScript
- **UI 库**: Naive UI
- **状态管理**: Pinia
- **路由**: Vue Router
- **HTTP 客户端**: Axios
- **国际化**: Vue I18n (支持中英文)

## 快速开始

### 环境要求

- Docker & Docker Compose
- Go 1.20+
- Node.js 18+
- OpenResty 1.21+

### 安装步骤

1. **克隆项目**
   ```bash
   git clone <repository-url>
   cd waf-project
   ```

2. **启动服务**
   ```bash
   docker-compose up -d
   ```

3. **访问管理面板**
   ```
   http://localhost:80
   ```

### 开发模式

#### 后端开发

```bash
cd backend
go run cmd/main.go
```

#### 前端开发

```bash
cd frontend
npm install
npm run dev
```

## API 接口

### 认证相关

- `POST /api/v1/auth/login` - 用户登录
- `POST /api/v1/auth/refresh` - 刷新令牌
- `POST /api/v1/auth/logout` - 用户登出

### 规则管理

- `GET /api/v1/rules` - 获取规则列表
- `POST /api/v1/rules` - 创建规则
- `PUT /api/v1/rules/:id` - 更新规则
- `DELETE /api/v1/rules/:id` - 删除规则

### IP 列表管理

- `GET /api/v1/ip-list` - 获取 IP 列表
- `POST /api/v1/ip-list` - 添加 IP
- `DELETE /api/v1/ip-list/:id` - 删除 IP

### 日志查询

- `GET /api/v1/logs` - 获取日志列表
- `GET /api/v1/logs/:id` - 获取日志详情

### 仪表盘

- `GET /api/v1/dashboard/stats` - 获取统计数据
- `GET /api/v1/dashboard/chart` - 获取图表数据

## 配置说明

### 后端配置

配置文件位于 `backend/configs/config.yaml`，支持环境变量覆盖。

```yaml
server:
  port: 8080
  mode: release

database:
  host: localhost
  port: 5432
  user: postgres
  password: postgres
  dbname: waf
  sslmode: disable

redis:
  host: localhost
  port: 6379
  password: ""
  db: 0

jwt:
  secret: your-secret-key
  access_token_ttl: 3600
  refresh_token_ttl: 86400
```

### OpenResty 配置

配置文件位于 `openresty/conf/nginx.conf`，主要配置项包括：

- 共享内存区域配置
- Lua 脚本路径配置
- Redis 连接池配置
- 上游服务器配置

## 安全特性

### 数据脱敏

系统自动检测并脱敏以下敏感信息：

- 身份证号
- 手机号
- 银行卡号
- 邮箱地址
- IP 地址（可选）

### 速率限制

支持多种速率限制策略：

- 基于 IP 的请求频率限制
- 基于用户的请求配额限制
- 基于路径的访问频率限制

### 规则引擎

支持自定义过滤规则：

- URI 匹配规则
- 请求头匹配规则
- 请求体匹配规则
- 组合条件规则

## 性能优化

- **连接池**: Redis 和数据库连接池复用
- **缓存**: 规则缓存、配置缓存
- **异步日志**: 非阻塞日志写入
- **共享内存**: Nginx shared dict 高性能缓存

## 文档

- [流量过滤流程详解](docs/流量过滤流程详解.md)
- [分析器性能优化计划](.trae/documents/分析器性能优化计划.md)

## 开发计划

- [ ] 支持更多攻击检测类型
- [ ] 增强规则引擎功能
- [ ] 优化性能监控
- [ ] 支持集群部署
- [ ] 增加机器学习检测能力

## 许可证

本项目采用 MIT 许可证。

## 贡献

欢迎提交 Issue 和 Pull Request！

## 联系方式

如有问题或建议，请通过 Issue 联系我们。
