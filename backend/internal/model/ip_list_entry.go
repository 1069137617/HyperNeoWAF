package model

import (
	"time"

	"gorm.io/gorm"
)

// IPListEntry - IP 黑名单/白名单条目模型
// 支持永久或临时条目，包含 IP 地址、类型（黑/白名单）、原因、来源等信息
type IPListEntry struct {
	ID        uint           `gorm:"primaryKey" json:"id"`
	IP        string         `gorm:"size:45;uniqueIndex;not null" json:"ip"`
	Type      string         `gorm:"size:10;not null;index" json:"type"`
	Reason    string         `gorm:"size:500" json:"reason"`
	ExpiresAt *time.Time     `json:"expires_at,omitempty"`
	AddedBy   uint           `json:"added_by"`
	Source    string         `gorm:"size:30;default:manual" json:"source"`
	IsActive  bool           `gorm:"default:true;index" json:"is_active"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`
}

// IPListTypes - IP 列表类型常量
// blacklist: 黑名单（拒绝访问）; whitelist: 白名单（允许访问）
var IPListTypes = struct {
	Blacklist string
	Whitelist string
}{
	Blacklist: "blacklist",
	Whitelist: "whitelist",
}

// IPListSources - 条目来源常量
// manual: 手动添加; auto_block: 自动封禁; api: API 添加; public_library: 公开IP库
var IPListSources = struct {
	Manual         string
	AutoBlock      string
	API            string
	PublicLibrary  string
}{
	Manual:         "manual",
	AutoBlock:      "auto_block",
	API:            "api",
	PublicLibrary:  "public_library",
}

// TableName - 指定 IPListEntry 模型对应的数据库表名
func (IPListEntry) TableName() string {
	return "ip_list_entries"
}

// IsExpired - 检查条目是否已过期
// 如果 ExpiresAt 为 nil，则永久有效，返回 false
func (e *IPListEntry) IsExpired() bool {
	if e.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*e.ExpiresAt)
}
