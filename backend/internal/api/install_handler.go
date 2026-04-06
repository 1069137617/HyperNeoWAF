package api

import (
	"fmt"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/waf-project/backend/internal/database"
	"github.com/waf-project/backend/internal/model"
	"github.com/waf-project/backend/internal/repository"
	"github.com/waf-project/backend/internal/service"
)

type InstallHandler struct {
	authService *service.AuthService
}

func NewInstallHandler(authService *service.AuthService) *InstallHandler {
	return &InstallHandler{
		authService: authService,
	}
}

type CheckDepsRequest struct {
	DBHost     string `json:"db_host"`
	DBPort     int    `json:"db_port"`
	DBUser     string `json:"db_user"`
	DBPassword string `json:"db_password"`
	DBName     string `json:"db_name"`
	RedisHost  string `json:"redis_host"`
	RedisPort  int    `json:"redis_port"`
}

type CheckDepsResponse struct {
	Success  bool             `json:"success"`
	Database DependencyStatus `json:"database"`
	Redis    DependencyStatus `json:"redis"`
}

type DependencyStatus struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

func (h *InstallHandler) CheckDependencies(c *gin.Context) {
	var req CheckDepsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Bad Request",
			"message": "Invalid request: " + err.Error(),
		})
		return
	}

	resp := CheckDepsResponse{
		Success: true,
		Database: DependencyStatus{
			Status:  "checking",
			Message: "正在检查数据库连接...",
		},
		Redis: DependencyStatus{
			Status:  "checking",
			Message: "正在检查 Redis 连接...",
		},
	}

	if req.DBHost != "" {
		dbConfig := &database.Config{
			Host:     req.DBHost,
			Port:     req.DBPort,
			User:     req.DBUser,
			Password: req.DBPassword,
			DBName:   req.DBName,
			SSLMode:  "disable",
		}
		if err := database.TestConnection(dbConfig); err != nil {
			resp.Database = DependencyStatus{
				Status:  "failed",
				Message: "数据库连接失败: " + err.Error(),
			}
			resp.Success = false
		} else {
			resp.Database = DependencyStatus{
				Status:  "ok",
				Message: "数据库连接成功",
			}
		}
	}

	if req.RedisHost != "" {
		redisClient := repository.NewRedisClient(&repository.RedisConfig{
			Host: req.RedisHost,
			Port: req.RedisPort,
		})
		if err := redisClient.Ping(); err != nil {
			resp.Redis = DependencyStatus{
				Status:  "failed",
				Message: "Redis 连接失败: " + err.Error(),
			}
			resp.Success = false
		} else {
			resp.Redis = DependencyStatus{
				Status:  "ok",
				Message: "Redis 连接成功",
			}
			redisClient.Close()
		}
	}

	if !resp.Success && resp.Database.Status == "checking" && resp.Redis.Status == "checking" {
		resp.Database = DependencyStatus{
			Status:  "skipped",
			Message: "跳过数据库检查",
		}
		resp.Redis = DependencyStatus{
			Status:  "skipped",
			Message: "跳过 Redis 检查",
		}
	}

	c.JSON(http.StatusOK, resp)
}

type InstallRequest struct {
	DBHost        string `json:"db_host" binding:"required"`
	DBPort        int    `json:"db_port" binding:"required"`
	DBUser        string `json:"db_user" binding:"required"`
	DBPassword    string `json:"db_password" binding:"required"`
	DBName        string `json:"db_name" binding:"required"`
	RedisHost     string `json:"redis_host" binding:"required"`
	RedisPort     int    `json:"redis_port" binding:"required"`
	RedisPassword string `json:"redis_password"`
	AdminUsername string `json:"admin_username" binding:"required,min=3,max=50"`
	AdminPassword string `json:"admin_password" binding:"required,min=8,max=128"`
	JWTSecret     string `json:"jwt_secret"`
}

type InstallResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

func (h *InstallHandler) Install(c *gin.Context) {
	var req InstallRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Bad Request",
			"message": "Invalid request: " + err.Error(),
		})
		return
	}

	dbConfig := &database.Config{
		Host:            req.DBHost,
		Port:            req.DBPort,
		User:            req.DBUser,
		Password:        req.DBPassword,
		DBName:          req.DBName,
		SSLMode:         "disable",
		MaxOpenConns:    100,
		MaxIdleConns:    10,
		ConnMaxLifetime: 3600,
	}

	if err := database.Initialize(dbConfig); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "数据库初始化失败: " + err.Error(),
		})
		return
	}

	redisClient := repository.NewRedisClient(&repository.RedisConfig{
		Host:     req.RedisHost,
		Port:     req.RedisPort,
		Password: req.RedisPassword,
		DB:       0,
		PoolSize: 100,
	})
	if err := redisClient.Ping(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "Redis 连接失败: " + err.Error(),
		})
		return
	}

	// 自动开启 Redis 持久化
	persistenceEnabled, persistErr := repository.EnablePersistence(
		req.RedisHost,
		req.RedisPort,
		req.RedisPassword,
	)
	if !persistenceEnabled {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "Redis 持久化配置失败: " + persistErr.Error(),
		})
		return
	}

	redisClient.Close()

	_, err := h.authService.CreateUser(req.AdminUsername, req.AdminPassword, "admin")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "创建管理员账户失败: " + err.Error(),
		})
		return
	}

	jwtSecret := req.JWTSecret
	if jwtSecret == "" {
		jwtSecret = "waf-secret-key-" + req.AdminUsername + "-installed"
	}

	configContent := generateConfigFile(req, jwtSecret)
	configPath := "configs/config.yaml"
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "配置文件写入失败: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "安装成功！",
	})
}

func generateConfigFile(req InstallRequest, jwtSecret string) string {
	dbPort := fmt.Sprintf("%d", req.DBPort)
	redisPort := fmt.Sprintf("%d", req.RedisPort)
	redisPassword := req.RedisPassword
	if redisPassword == "" {
		redisPassword = "\"\"" // empty string representation
	}

	return fmt.Sprintf(`# WAF 后端服务配置文件
# 配置文件格式：YAML
# 环境变量覆盖：CONFIG_PATH 指定配置文件路径

# ==================== 服务器配置 ====================
server:
  port: 8080                              # HTTP 服务监听端口
  mode: debug                             # 运行模式: debug(调试) / release(发布) / test(测试)

# ==================== 数据库配置 ====================
database:
  host: %s                         # PostgreSQL 数据库主机地址
  port: %s                              # PostgreSQL 端口号
  user: %s                         # 数据库用户名
  password: %s      # 数据库密码
  dbname: %s                          # 数据库名称
  sslmode: disable                        # SSL 模式: disable / allow / prefer / require / verify-ca / verify-full
  max_open_conns: 100                      # 最大打开连接数
  max_idle_conns: 10                       # 最大空闲连接数
  conn_max_lifetime: 3600                  # 连接最大生命周期（秒）

# ==================== Redis 配置 ====================
redis:
  host: %s                         # Redis 服务器地址
  port: %s                              # Redis 端口号
  password: %s         # Redis 密码（支持环境变量，默认空）
  db: 0                                   # Redis 数据库编号（0-15）
  pool_size: 100                           # 连接池大小

# ==================== JWT 认证配置 ====================
jwt:
  # JWT 签名密钥
  secret: %s
  access_token_ttl: 24h                   # Access Token 有效期（24小时）
  refresh_token_ttl: 168h                 # Refresh Token 有效期（168小时 = 7天）

# ==================== 日志配置 ====================
logging:
  level: info                             # 日志级别: debug / info / warn / error
  format: json                             # 日志格式: json / text
`, req.DBHost, dbPort, req.DBUser, req.DBPassword, req.DBName,
		req.RedisHost, redisPort, redisPassword, jwtSecret)
}

type CheckInstalledResponse struct {
	Installed bool `json:"installed"`
}

func (h *InstallHandler) CheckInstalled(c *gin.Context) {
	db := database.GetDB()
	if db == nil {
		c.JSON(http.StatusOK, gin.H{
			"installed": false,
		})
		return
	}

	var count int64
	db.Model(&model.User{}).Where("role = ?", "admin").Count(&count)

	c.JSON(http.StatusOK, gin.H{
		"installed": count > 0,
	})
}
