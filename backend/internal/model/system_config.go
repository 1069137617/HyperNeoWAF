package model

import (
	"time"

	"gorm.io/gorm"
)

// SystemConfig - 系统配置模型，存储键值对形式的配置
// 支持多种数据类型：字符串、数字、布尔、JSON；可按组分类，支持公开/私有配置
type SystemConfig struct {
	ID        uint           `gorm:"primaryKey" json:"id"`
	Key       string         `gorm:"size:100;uniqueIndex;not null" json:"key"`
	Value     string         `gorm:"type:text" json:"value"`
	ValueType string         `gorm:"size:20;default:string" json:"value_type"`
	Group     string         `gorm:"size:50;index" json:"group"`
	IsPublic  bool           `gorm:"default:false" json:"is_public"`
	UpdatedAt time.Time      `json:"updated_at"`
	CreatedAt time.Time      `json:"created_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`
}

// ConfigGroups - 配置分组常量
// general: 通用配置; security: 安全配置; redis: Redis 配置; logging: 日志配置; jwt: JWT 配置; server: 服务器配置
var ConfigGroups = struct {
	General  string
	Security string
	Redis    string
	Logging  string
	JWT      string
	Server   string
}{
	General:  "general",
	Security: "security",
	Redis:    "redis",
	Logging:  "logging",
	JWT:      "jwt",
	Server:   "server",
}

// ValueTypes - 配置值类型常量
// string: 字符串; number: 数字; boolean: 布尔; json: JSON 格式
var ValueTypes = struct {
	String  string
	Number  string
	Boolean string
	JSON    string
}{
	String:  "string",
	Number:  "number",
	Boolean: "boolean",
	JSON:    "json",
}

// TableName - 指定 SystemConfig 模型对应的数据库表名
func (SystemConfig) TableName() string {
	return "system_configs"
}
