package repository

import (
	"context"
	"time"
)

// RedisClient - Redis 客户端接口，定义 Redis 操作的抽象方法
// 支持基本的键值操作、批量命令执行、连接管理等功能
type RedisClient interface {
	// Set - 设置键值对，可指定过期时间（秒）
	Set(key string, value interface{}, expiration int64) error
	// Get - 获取指定键的值
	Get(key string) (string, error)
	// Del - 删除一个或多个键
	Del(keys ...string) error
	// Exists - 检查一个或多个键是否存在
	Exists(keys ...string) (int64, error)
	// Keys - 根据模式查找所有匹配的键
	Keys(pattern string) ([]string, error)
	// Pipeline - 执行批量 Redis 命令
	Pipeline(commands ...RedisCommand) ([]interface{}, error)
	// Ping - 检查 Redis 连接是否正常
	Ping() error
	// Close - 关闭 Redis 连接
	Close() error
}

// RedisCommand - Redis 命令结构体
// 包含命令名称和参数列表，用于批量执行命令
type RedisCommand struct {
	Cmd  string        // Redis 命令名称（如 GET, SET, HGET 等）
	Args []interface{} // 命令参数列表
}

// RedisConfig - Redis 连接配置结构体
// 包含连接 Redis 服务器所需的所有参数
type RedisConfig struct {
	Host     string // Redis 服务器主机地址
	Port     int    // Redis 服务器端口
	Password string // Redis 认证密码（为空表示不需要认证）
	DB       int    // Redis 数据库编号（0-15）
	PoolSize int    // 连接池大小
}

// EnablePersistence - 启用 Redis 持久化
// 自动开启 RDB 快照和 AOF 持久化，确保数据安全
// 返回是否成功启用以及错误信息
func EnablePersistence(host string, port int, password string) (bool, error) {
	tempClient := NewRedisClient(&RedisConfig{
		Host:     host,
		Port:     port,
		Password: password,
		DB:       0,
		PoolSize: 1,
	})

	if err := tempClient.Ping(); err != nil {
		tempClient.Close()
		return false, err
	}

	// 启用 RDB 快照（每秒一次）
	rdbResult, rdbErr := tempClient.Execute("CONFIG", "SET", "save", "900 1 300 10 60 10000")
	if rdbErr != nil {
		tempClient.Close()
		return false, rdbErr
	}
	_ = rdbResult

	// 启用 AOF 持久化（每秒同步）
	aofResult, aofErr := tempClient.Execute("CONFIG", "SET", "appendonly", "yes")
	if aofErr != nil {
		tempClient.Close()
		return false, aofErr
	}
	_ = aofResult

	// 设置 AOF 同步模式为 everysec
	aofSyncResult, aofSyncErr := tempClient.Execute("CONFIG", "SET", "appendfsync", "everysec")
	if aofSyncErr != nil {
		tempClient.Close()
		return false, aofSyncErr
	}
	_ = aofSyncResult

	tempClient.Close()
	return true, nil
}
