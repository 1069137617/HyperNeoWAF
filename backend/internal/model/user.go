package model

import (
	"time"

	"gorm.io/gorm"
)

// User - 用户模型，表示 WAF 管理面板的管理员账户
// 包含用户名、密码哈希、角色、活跃状态和最后登录时间等字段
type User struct {
	ID           uint           `gorm:"primaryKey" json:"id"`
	Username     string         `gorm:"uniqueIndex;size:50;not null" json:"username"`
	PasswordHash string         `gorm:"size:255;not null" json:"-"`
	Role         string         `gorm:"size:20;default:admin;index" json:"role"`
	IsActive     bool           `gorm:"default:true;index" json:"is_active"`
	LastLoginAt  *time.Time     `json:"last_login_at"`
	CreatedAt    time.Time      `json:"created_at"`
	UpdatedAt    time.Time      `json:"updated_at"`
	DeletedAt    gorm.DeletedAt `gorm:"index" json:"-"`
}

// TableName - 指定 User 模型对应的数据库表名
func (User) TableName() string {
	return "users"
}

// UserRoles - 用户角色常量定义
// 支持三种角色：admin（管理员）、editor（编辑者）、viewer（查看者）
var UserRoles = struct {
	Admin  string
	Editor string
	Viewer string
}{
	Admin:  "admin",
	Editor: "editor",
	Viewer: "viewer",
}
