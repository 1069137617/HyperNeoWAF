package main

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/waf-project/backend/internal/api"
	"github.com/waf-project/backend/internal/database"
	"github.com/waf-project/backend/internal/middleware"
	"github.com/waf-project/backend/internal/repository"
	"github.com/waf-project/backend/internal/service"
)

// staticFiles - 嵌入的前端静态文件目录
// 通过 //go:embed 指令将编译后的 Vue.js 前端资源打包到二进制文件中
// 实现单端口架构：Go Backend 同时提供 API 和静态文件服务
//
//go:embed web/*
var staticFiles embed.FS

// main - WAF 后端服务入口函数
// 初始化顺序：配置加载 → 数据库连接 → Redis 连接 → JWT 认证 → 服务层 → 路由注册 → 启动服务器
func main() {
	// 1. 加载配置文件（支持 YAML 文件和环境变量覆盖）
	config := loadConfig()

	// 2. 设置 Gin 框架运行模式（debug/release/test）
	gin.SetMode(config.Server.Mode)

	// 3. 创建 Gin 路由引擎，注册全局中间件
	router := gin.New()
	router.Use(gin.Recovery())             // 恢复 panic 避免服务崩溃
	router.Use(middleware.CORSConfig())    // CORS 跨域资源共享
	router.Use(middleware.RequestLogger()) // 请求日志记录
	router.Use(middleware.Recovery())      // 额外的恢复中间件

	// 4. 初始化 PostgreSQL 数据库连接
	dbConfig := &database.Config{
		Host:            config.Database.Host,
		Port:            config.Database.Port,
		User:            config.Database.User,
		Password:        config.Database.Password,
		DBName:          config.Database.DBName,
		SSLMode:         config.Database.SSLMode,
		MaxOpenConns:    config.Database.MaxOpenConns,
		MaxIdleConns:    config.Database.MaxIdleConns,
		ConnMaxLifetime: time.Duration(config.Database.ConnMaxLifetime) * time.Second,
	}

	if err := database.Initialize(dbConfig); err != nil {
		log.Fatalf("数据库初始化失败: %v", err)
	}

	// 5. 初始化 Redis 客户端（用于缓存规则和会话管理）
	redisClient := repository.NewRedisClient(&repository.RedisConfig{
		Host:     config.Redis.Host,
		Port:     config.Redis.Port,
		Password: config.Redis.Password,
		DB:       config.Redis.DB,
		PoolSize: config.Redis.PoolSize,
	})

	// 6. 初始化 JWT 认证中间件（Access Token + Refresh Token 双令牌机制）
	jwtAuth := middleware.NewJWTAuth(
		config.JWT.Secret,
		time.Duration(config.JWT.AccessTokenTTL)*time.Second,  // Access Token 过期时间
		time.Duration(config.JWT.RefreshTokenTTL)*time.Second, // Refresh Token 过期时间
	)

	// 7. 初始化服务层（业务逻辑处理）
	authService := service.NewAuthService(database.GetDB())
	ruleService := service.NewRuleService(database.GetDB(), redisClient)
	logService := service.NewLogService(database.GetDB(), redisClient)
	ipListService := service.NewIPListService(database.GetDB(), redisClient)
	dashboardService := service.NewDashboardService(database.GetDB())

	// 8. 初始化 API 处理器（HTTP 请求处理）
	authHandler := api.NewAuthHandler(authService, jwtAuth)
	ruleHandler := api.NewRuleHandler(ruleService)
	logHandler := api.NewLogHandler(logService)
	ipListHandler := api.NewIPListHandler(ipListService)
	dashboardHandler := api.NewDashboardHandler(dashboardService, logService)
	installHandler := api.NewInstallHandler(authService)

	// 9. 注册健康检查端点（用于负载均衡器探活）
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":  "healthy",
			"service": "waf-backend",
			"time":    time.Now().UTC(),
		})
	})

	// 10. 注册 API 路由
	apiV1 := router.Group("/api/v1")
	{
		// 公开接口（无需认证）
		auth := apiV1.Group("/auth")
		{
			auth.POST("/login", authHandler.Login)          // 用户登录
			auth.POST("/refresh", authHandler.RefreshToken) // 刷新 Token
		}

		// 安装接口（无需认证）
		install := apiV1.Group("/install")
		{
			install.GET("/check", installHandler.CheckInstalled)          // 检查是否已安装
			install.POST("/check-deps", installHandler.CheckDependencies) // 检查依赖连接
			install.POST("/do", installHandler.Install)                   // 执行安装
		}

		// 受保护接口（需要 JWT 认证）
		protected := apiV1.Group("")
		protected.Use(jwtAuth.AuthMiddleware())
		{
			// 认证相关（需要认证但不是管理员）
			authProtected := protected.Group("/auth")
			authProtected.GET("/profile", authHandler.GetProfile)      // 获取用户信息
			authProtected.PUT("/password", authHandler.ChangePassword) // 修改密码

			// 规则管理 CRUD
			rules := protected.Group("/rules")
			rules.GET("", ruleHandler.ListRules)             // 列出规则（分页、筛选）
			rules.POST("", ruleHandler.CreateRule)           // 创建规则
			rules.GET("/:id", ruleHandler.GetRule)           // 获取单个规则
			rules.PUT("/:id", ruleHandler.UpdateRule)        // 更新规则
			rules.DELETE("/:id", ruleHandler.DeleteRule)     // 删除规则
			rules.PUT("/sync", ruleHandler.SyncRulesToRedis) // 同步规则到 Redis

			// 安全日志
			logs := protected.Group("/logs")
			logs.POST("/receive", logHandler.ReceiveLogs) // 接收 OpenResty 日志
			logs.GET("", logHandler.ListLogs)             // 查询日志
			logs.GET("/:id", logHandler.GetLogByID)       // 获取单条日志
			logs.GET("/export", logHandler.ExportLogs)    // 导出日志（CSV/JSON）
			logs.GET("/stats", logHandler.GetLogStats)    // 日志统计

			// IP 黑白名单管理
			ipList := protected.Group("/ip-list")
			ipList.GET("", ipListHandler.ListIPs)                      // 列出 IP
			ipList.POST("", ipListHandler.AddIP)                       // 添加 IP
			ipList.POST("/batch-import", ipListHandler.BatchImportIPs) // 批量导入
			ipList.GET("/:id", ipListHandler.GetIPByID)                // 获取单个 IP 条目
			ipList.DELETE("/:id", ipListHandler.DeleteIP)              // 删除 IP
			ipList.PUT("/sync", ipListHandler.SyncIPsToRedis)          // 同步到 Redis

			// 仪表盘统计
			dash := protected.Group("/dashboard")
			dash.GET("/stats", dashboardHandler.GetStats)                // 总体统计
			dash.GET("/trends", dashboardHandler.GetTrends)              // 趋势数据
			dash.GET("/recent-events", dashboardHandler.GetRecentEvents) // 最近事件
			dash.GET("/top-attacks", dashboardHandler.GetTopAttacks)     // Top 攻击
			dash.GET("/qps", dashboardHandler.GetRealtimeQPS)            // 实时 QPS
		}
	}

	// 11. 配置静态文件服务器和 SPA Fallback
	setupStaticServer(router)

	// 12. 创建 HTTP 服务器
	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", config.Server.Port),
		Handler:      router,
		ReadTimeout:  10 * time.Second, // 读取请求超时
		WriteTimeout: 10 * time.Second, // 写入响应超时
		IdleTimeout:  60 * time.Second, // 空闲连接超时
	}

	// 13. 启动服务器（ goroutine 异步启动）
	go func() {
		log.Printf("[WAF Backend] 启动服务，监听端口 %d (模式: %s)", config.Server.Port, config.Server.Mode)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("服务器启动失败: %v", err)
		}
	}()

	// 14. 等待中断信号（SIGINT/SIGTERM）优雅关闭服务器
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("正在关闭服务器...")

	// 15. 优雅关闭：等待 30 秒处理中的请求
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("服务器强制关闭: %v", err)
	}

	// 16. 关闭数据库连接
	database.Close()
	log.Println("服务器已优雅退出")
}

// setupStaticServer - 配置静态文件服务器和 SPA Fallback
// 实现单端口架构：同一个端口同时提供 API 和 Vue.js 前端
// 非 API 路径返回 index.html，由 Vue Router 处理路由
func setupStaticServer(router *gin.Engine) {
	// 从嵌入的文件系统中获取 web 目录作为子文件系统
	webFS, err := fs.Sub(staticFiles, "web")
	if err != nil {
		log.Printf("警告: 无法获取前端子文件系统: %v", err)
		return
	}

	fileServer := http.FileServer(http.FS(webFS))

	// NoRoute 处理器：处理所有未匹配的路径
	router.NoRoute(func(c *gin.Context) {
		path := c.Request.URL.Path

		// API 路径返回 404（不应该走到这里）
		if len(path) >= 4 && path[:4] == "/api" {
			c.JSON(http.StatusNotFound, gin.H{"error": "API endpoint not found"})
			return
		}

		// 健康检查路径直接返回（不应该走到这里）
		if path == "/health" {
			return
		}

		// 尝试查找请求的文件
		f, err := webFS.Open(path[1:])
		if err == nil {
			f.Close()
			// 文件存在，直接服务
			fileServer.ServeHTTP(c.Writer, c.Request)
			return
		}

		// 文件不存在，返回 index.html（SPA Fallback）
		// 让 Vue Router 处理路由（History 模式需要）
		indexFile, err := webFS.Open("index.html")
		if err != nil {
			c.String(http.StatusInternalServerError, "前端未构建。请先运行 'cd frontend && npm run build'")
			return
		}
		indexFile.Close()

		// 修改路径为 /index.html 并服务
		c.Request.URL.Path = "/index.html"
		fileServer.ServeHTTP(c.Writer, c.Request)
	})

	log.Println("[静态文件服务] 已配置 SPA Fallback 支持")
}
