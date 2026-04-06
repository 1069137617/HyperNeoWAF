package model

import (
	"time"

	"gorm.io/gorm"
)

// Rule - WAF 安全规则模型，用于检测恶意请求
// 包含规则名称、类型、正则表达式匹配模式、触发动作、严重程度和优先级等字段
type Rule struct {
	ID          uint           `gorm:"primaryKey" json:"id"`
	Name        string         `gorm:"size:100;not null;index" json:"name"`
	Description string         `gorm:"size:500" json:"description"`
	Type        string         `gorm:"size:30;not null;index" json:"type"`
	Pattern     string         `gorm:"type:text;not null" json:"pattern"`
	Action      string         `gorm:"size:10;not null;default:deny" json:"action"`
	Severity    string         `gorm:"size:15;default:medium" json:"severity"`
	Priority    int            `gorm:"default:100;index" json:"priority"`
	Enabled     bool           `gorm:"default:true;index" json:"enabled"`
	Version     int            `gorm:"default:1" json:"version"`
	CreatedBy   uint           `json:"created_by"`
	UpdatedBy   uint           `json:"updated_by"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"-"`
}

// RuleTypes - 规则类型常量定义
// 支持：SQL注入、XSS、CC攻击、路径遍历、命令注入、SSI注入、XXE注入、自定义正则
var RuleTypes = struct {
	SQLInjection     string
	XSS              string
	CCAttack         string
	PathTraversal    string
	CommandInjection string
	SSIInjection     string
	XXEInjection     string
	CustomRegex      string
}{
	SQLInjection:     "sql_injection",
	XSS:              "xss",
	CCAttack:         "cc_attack",
	PathTraversal:    "path_traversal",
	CommandInjection: "command_injection",
	SSIInjection:     "ssi_injection",
	XXEInjection:     "xxe_injection",
	CustomRegex:      "custom_regex",
}

// RuleActions - 规则匹配时的动作常量
// deny: 拒绝请求; allow: 允许请求; log_only: 仅记录不阻止
var RuleActions = struct {
	Deny    string
	Allow   string
	LogOnly string
}{
	Deny:    "deny",
	Allow:   "allow",
	LogOnly: "log_only",
}

// RuleSeverities - 规则严重程度常量
// low: 低风险; medium: 中风险; high: 高风险; critical: 严重风险
var RuleSeverities = struct {
	Low      string
	Medium   string
	High     string
	Critical string
}{
	Low:      "low",
	Medium:   "medium",
	High:     "high",
	Critical: "critical",
}

// TableName - 指定 Rule 模型对应的数据库表名
func (Rule) TableName() string {
	return "rules"
}
