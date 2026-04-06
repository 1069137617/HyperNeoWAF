package database

import (
	"fmt"
	"log"
	"time"

	"github.com/waf-project/backend/internal/model"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// DB - 全局数据库实例，供其他包使用
var DB *gorm.DB

// Config - 数据库配置结构体
// 包含连接数据库所需的所有参数：主机地址、端口、用户名、密码、数据库名等
type Config struct {
	Host            string        // 数据库主机地址
	Port            int           // 数据库端口号
	User            string        // 数据库用户名
	Password        string        // 数据库密码
	DBName          string        // 数据库名称
	SSLMode         string        // SSL 模式（disable, allow, prefer, require, verify-ca, verify-full）
	MaxOpenConns    int           // 最大打开连接数
	MaxIdleConns    int           // 最大空闲连接数
	ConnMaxLifetime time.Duration // 连接最大生命周期
}

// Initialize - 初始化数据库连接并执行迁移
// 使用给定的配置创建数据库连接池，设置连接参数，并自动迁移所有模型表结构
func Initialize(config *Config) error {
	dsn := fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		config.Host,
		config.Port,
		config.User,
		config.Password,
		config.DBName,
		config.SSLMode,
	)

	var err error

	// 创建 GORM 数据库实例，配置日志模式
	DB, err = gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Info),
	})

	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}

	// 获取底层 sql.DB 实例以配置连接池
	sqlDB, err := DB.DB()
	if err != nil {
		return fmt.Errorf("failed to get underlying sql.DB: %w", err)
	}

	// 配置连接池参数
	sqlDB.SetMaxOpenConns(config.MaxOpenConns)
	sqlDB.SetMaxIdleConns(config.MaxIdleConns)
	sqlDB.SetConnMaxLifetime(config.ConnMaxLifetime)

	log.Println("Database connection established successfully")

	// 执行数据库迁移，创建所有模型对应的表
	err = AutoMigrate()
	if err != nil {
		return fmt.Errorf("failed to run migrations: %w", err)
	}

	return nil
}

// AutoMigrate - 执行数据库自动迁移
// 根据模型定义自动创建或更新数据库表结构
// 迁移的模型包括：User、Rule、SecurityLog、IPListEntry、SystemConfig
func AutoMigrate() error {
	return DB.AutoMigrate(
		&model.User{},
		&model.Rule{},
		&model.SecurityLog{},
		&model.IPListEntry{},
		&model.SystemConfig{},
	)
}

// GetDB - 获取数据库实例
// 返回全局的 GORM 数据库对象，供其他服务层使用
func GetDB() *gorm.DB {
	return DB
}

// HealthCheck - 健康检查，验证数据库连接是否正常
// 通过 ping 命令检测数据库连通性
func HealthCheck() error {
	sqlDB, err := DB.DB()
	if err != nil {
		return err
	}
	return sqlDB.Ping()
}

func TestConnection(config *Config) error {
	dsn := fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		config.Host,
		config.Port,
		config.User,
		config.Password,
		config.DBName,
		config.SSLMode,
	)

	_, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})

	return err
}

// Close - 关闭数据库连接
// 在应用关闭时调用，释放所有数据库连接资源
func Close() error {
	sqlDB, err := DB.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}
