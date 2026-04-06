package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config - 应用程序配置结构体
// 包含所有配置项：服务器、数据库、Redis、JWT、Logging
type Config struct {
	Server   ServerConfig   `yaml:"server"`   // 服务器配置
	Database DatabaseConfig `yaml:"database"` // PostgreSQL 数据库配置
	Redis    RedisConfig    `yaml:"redis"`    // Redis 配置
	JWT      JWTConfig      `yaml:"jwt"`      // JWT 认证配置
	Logging  LoggingConfig  `yaml:"logging"`  // 日志配置
}

// ServerConfig - HTTP 服务器配置
type ServerConfig struct {
	Port int    `yaml:"port"` // 监听端口号
	Mode string `yaml:"mode"` // 运行模式：debug（调试）、release（发布）、test（测试）
}

// DatabaseConfig - PostgreSQL 数据库连接配置
type DatabaseConfig struct {
	Host            string        `yaml:"host"`              // 数据库主机地址
	Port            int           `yaml:"port"`              // 数据库端口号
	User            string        `yaml:"user"`              // 数据库用户名
	Password        string        `yaml:"password"`          // 数据库密码
	DBName          string        `yaml:"dbname"`            // 数据库名称
	SSLMode         string        `yaml:"sslmode"`           // SSL 连接模式：disable、allow、prefer、require、verify-ca、verify-full
	MaxOpenConns    int           `yaml:"max_open_conns"`    // 最大打开连接数
	MaxIdleConns    int           `yaml:"max_idle_conns"`    // 最大空闲连接数
	ConnMaxLifetime time.Duration `yaml:"conn_max_lifetime"` // 连接最大生命周期（秒）
}

// RedisConfig - Redis 连接配置
type RedisConfig struct {
	Host     string `yaml:"host"`      // Redis 服务器地址
	Port     int    `yaml:"port"`      // Redis 端口号
	Password string `yaml:"password"`  // Redis 密码（空字符串表示无需认证）
	DB       int    `yaml:"db"`        // Redis 数据库编号（0-15）
	PoolSize int    `yaml:"pool_size"` // 连接池大小
}

// JWTConfig - JWT 认证配置
type JWTConfig struct {
	Secret          string        `yaml:"secret"`            // JWT 签名密钥（生产环境必须使用强密钥）
	AccessTokenTTL  time.Duration `yaml:"access_token_ttl"`  // Access Token 有效期（如 24h）
	RefreshTokenTTL time.Duration `yaml:"refresh_token_ttl"` // Refresh Token 有效期（如 168h = 7天）
}

// LoggingConfig - 日志配置
type LoggingConfig struct {
	Level  string `yaml:"level"`  // 日志级别：debug、info、warn、error
	Format string `yaml:"format"` // 日志格式：json、text
}

// loadConfig - 加载配置文件
// 优先级：1. CONFIG_PATH 环境变量指定的文件 > 2. configs/config.yaml > 3. 默认配置
// 支持通过环境变量覆盖特定配置项
func loadConfig() *Config {
	// 1. 确定配置文件路径（支持环境变量自定义）
	configPath := os.Getenv("CONFIG_PATH")
	if configPath == "" {
		configPath = "configs/config.yaml" // 默认配置文件位置
	}

	// 2. 读取配置文件
	data, err := os.ReadFile(configPath)
	if err != nil {
		log.Printf("警告: 无法读取配置文件: %v，使用默认配置", err)
		return defaultConfig()
	}

	// 3. 解析 YAML 配置
	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		log.Printf("警告: 配置文件解析失败: %v，使用默认配置", err)
		return defaultConfig()
	}

	// 4. 使用环境变量覆盖配置（适用于容器化部署）
	// SERVER_PORT: 覆盖服务器端口
	if port := os.Getenv("SERVER_PORT"); port != "" {
		fmt.Sscanf(port, "%d", &config.Server.Port)
	}
	// SERVER_MODE: 覆盖运行模式
	if mode := os.Getenv("SERVER_MODE"); mode != "" {
		config.Server.Mode = mode
	}

	return &config
}

// defaultConfig - 返回默认配置
// 当配置文件不存在或解析失败时使用
func defaultConfig() *Config {
	return &Config{
		// 默认服务器配置：监听 8080 端口，调试模式
		Server: ServerConfig{
			Port: 8080,
			Mode: "debug",
		},
		// 默认数据库配置（仅用于本地开发）
		Database: DatabaseConfig{
			Host:         "localhost",
			Port:         5432,
			User:         "waf_admin",
			Password:     "changeme", // 开发环境密码，生产环境必须修改
			DBName:       "waf_db",
			SSLMode:      "disable",
			MaxOpenConns: 100,
			MaxIdleConns: 10,
		},
		// 默认 Redis 配置（本地开发）
		Redis: RedisConfig{
			Host:     "localhost",
			Port:     6379,
			Password: "",
			DB:       0,
			PoolSize: 100,
		},
		// 默认 JWT 配置
		JWT: JWTConfig{
			Secret:          "super-secret-key-change-in-production", // 开发环境密钥，生产必须修改
			AccessTokenTTL:  24 * time.Hour,                          // Access Token 24小时有效
			RefreshTokenTTL: 168 * time.Hour,                         // Refresh Token 7天有效
		},
		// 默认日志配置
		Logging: LoggingConfig{
			Level:  "info",
			Format: "json", // JSON 格式便于日志收集系统处理
		},
	}
}
