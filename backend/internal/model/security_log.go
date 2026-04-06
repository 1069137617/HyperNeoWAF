package model

import (
	"time"

	"gorm.io/gorm"
)

// SecurityLog - 安全日志模型，记录来自 OpenResty 的安全事件
// 包含客户端信息（已脱敏）、请求详情、WAF 判定结果、性能指标等
type SecurityLog struct {
	ID           uint      `gorm:"primaryKey" json:"id"`
	Timestamp    time.Time `gorm:"index" json:"timestamp"`
	TimestampISO string    `gorm:"size:30;index" json:"timestamp_iso"`

	ClientIP string `gorm:"size:45;index" json:"client_ip"`

	Method   string `gorm:"size:10;index" json:"method"`
	URI      string `gorm:"type:text" json:"uri"`
	Args     string `gorm:"type:text" json:"args"`
	Protocol string `gorm:"size:20" json:"protocol"`

	HeadersJSON string `gorm:"type:jsonb" json:"headers,omitempty"`

	StatusCode int `gorm:"index" json:"status_code"`

	WAFAction string `gorm:"size:10;index" json:"waf_action"`
	WAFRule   string `gorm:"size:200;index" json:"waf_rule"`
	WAFReason string `gorm:"size:500" json:"waf_reason"`

	RateLimitCurrent *int    `json:"rate_limit_current,omitempty"`
	RateLimitMax     *int    `json:"rate_limit_max,omitempty"`
	RateLimitReason  *string `json:"rate_limit_reason,omitempty"`

	RequestTime   float64 `json:"request_time"`
	BytesSent     int64   `json:"bytes_sent"`
	BodyBytesSent int64   `json:"body_bytes_sent"`

	BodyJSON string `gorm:"type:jsonb" json:"body,omitempty"`

	Source      string     `gorm:"size:20;default:openresty-waf;index" json:"source"`
	BatchID     string     `gorm:"size:64;index" json:"batch_id,omitempty"`
	ProcessedAt *time.Time `json:"processed_at,omitempty"`

	CreatedAt time.Time      `json:"created_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`
}

// WAFActions - WAF 动作类型常量
// allow: 允许通过; deny: 拒绝请求; rate_limited: 请求被限流
var WAFActions = struct {
	Allow       string
	Deny        string
	RateLimited string
}{
	Allow:       "allow",
	Deny:        "deny",
	RateLimited: "rate_limited",
}

// TableName - 指定 SecurityLog 模型对应的数据库表名
func (SecurityLog) TableName() string {
	return "security_logs"
}
