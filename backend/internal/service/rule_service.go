package service

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/waf-project/backend/internal/model"
	"github.com/waf-project/backend/internal/repository"
	"gorm.io/gorm"
)

var (
	ErrRuleNotFound    = errors.New("rule not found")
	ErrInvalidRuleType = errors.New("invalid rule type")
)

// RuleService handles rule management operations
type RuleService struct {
	db          *gorm.DB
	redisClient repository.RedisClient
}

// NewRuleService creates a new RuleService instance
func NewRuleService(db *gorm.DB, redisClient repository.RedisClient) *RuleService {
	return &RuleService{
		db:          db,
		redisClient: redisClient,
	}
}

// CreateRuleRequest represents request to create a new rule
type CreateRuleRequest struct {
	Name        string `json:"name" binding:"required,min=1,max=100"`
	Description string `json:"description,omitempty"`
	Type        string `json:"type" binding:"required"`
	Pattern     string `json:"pattern" binding:"required"`
	Action      string `json:"action" binding:"required"`
	Severity    string `json:"severity,omitempty"`
	Priority    int    `json:"priority,omitempty"`
}

// UpdateRuleRequest represents request to update an existing rule
type UpdateRuleRequest struct {
	Name        *string `json:"name,omitempty"`
	Description *string `json:"description,omitempty"`
	Pattern     *string `json:"pattern,omitempty"`
	Action      *string `json:"action,omitempty"`
	Severity    *string `json:"severity,omitempty"`
	Priority    *int    `json:"priority,omitempty"`
	Enabled     *bool   `json:"enabled,omitempty"`
}

// ListRulesResponse represents paginated rules list response
type ListRulesResponse struct {
	Data       []model.Rule `json:"data"`
	Total      int64        `json:"total"`
	Page       int          `json:"page"`
	PageSize   int          `json:"page_size"`
	TotalPages int          `json:"total_pages"`
}

// CreateRule creates a new WAF security rule
func (s *RuleService) CreateRule(req *CreateRuleRequest, createdBy uint) (*model.Rule, error) {
	// Validate rule type
	if !isValidRuleType(req.Type) {
		return nil, ErrInvalidRuleType
	}

	rule := model.Rule{
		Name:        req.Name,
		Description: req.Description,
		Type:        req.Type,
		Pattern:     req.Pattern,
		Action:      req.Action,
		Severity:    req.Severity,
		Priority:    req.Priority,
		Enabled:     true,
		CreatedBy:   createdBy,
		UpdatedBy:   createdBy,
	}

	if rule.Severity == "" {
		rule.Severity = "medium"
	}
	if rule.Priority == 0 {
		rule.Priority = 100
	}

	result := s.db.Create(&rule)
	if result.Error != nil {
		return nil, result.Error
	}

	// Sync to Redis after creation
	s.syncRuleToRedis(&rule)

	return &rule, nil
}

// GetRuleByID retrieves a single rule by ID
func (s *RuleService) GetRuleByID(ruleID uint) (*model.Rule, error) {
	var rule model.Rule
	result := s.db.First(&rule, ruleID)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, ErrRuleNotFound
		}
		return nil, result.Error
	}
	return &rule, nil
}

// ListRules retrieves paginated list of rules with optional filtering
func (s *RuleService) ListRules(page, pageSize int, filters map[string]interface{}) (*ListRulesResponse, error) {
	query := s.db.Model(&model.Rule{})

	// Apply filters
	for key, value := range filters {
		switch key {
		case "type":
			query = query.Where("type = ?", value)
		case "enabled":
			query = query.Where("enabled = ?", value)
		case "action":
			query = query.Where("action = ?", value)
		case "search":
			query = query.Where("name ILIKE ? OR description ILIKE ?", "%"+value.(string)+"%", "%"+value.(string)+"%")
		}
	}

	// Count total records
	var total int64
	query.Count(&total)

	// Calculate pagination
	offset := (page - 1) * pageSize
	totalPages := int((total + int64(pageSize) - 1) / int64(pageSize))

	// Fetch paginated results
	var rules []model.Rule
	result := query.Order("priority ASC, id DESC").Offset(offset).Limit(pageSize).Find(&rules)
	if result.Error != nil {
		return nil, result.Error
	}

	return &ListRulesResponse{
		Data:       rules,
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	}, nil
}

// UpdateRule updates an existing rule
func (s *RuleService) UpdateRule(ruleID uint, req *UpdateRuleRequest, updatedBy uint) (*model.Rule, error) {
	var rule model.Rule
	result := s.db.First(&rule, ruleID)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, ErrRuleNotFound
		}
		return nil, result.Error
	}

	// Apply updates
	updates := make(map[string]interface{})
	updates["updated_by"] = updatedBy
	updates["version"] = gorm.Expr("version + 1")

	if req.Name != nil {
		updates["name"] = *req.Name
	}
	if req.Description != nil {
		updates["description"] = *req.Description
	}
	if req.Pattern != nil {
		updates["pattern"] = *req.Pattern
	}
	if req.Action != nil {
		if !isValidAction(*req.Action) {
			return nil, errors.New("invalid action")
		}
		updates["action"] = *req.Action
	}
	if req.Severity != nil {
		updates["severity"] = *req.Severity
	}
	if req.Priority != nil {
		updates["priority"] = *req.Priority
	}
	if req.Enabled != nil {
		updates["enabled"] = *req.Enabled
	}

	result = s.db.Model(&rule).Updates(updates)
	if result.Error != nil {
		return nil, result.Error
	}

	// Reload updated data
	s.db.First(&rule, ruleID)

	// Sync to Redis after update
	s.syncRuleToRedis(&rule)

	return &rule, nil
}

// DeleteRule soft-deletes a rule by ID
func (s *RuleService) DeleteRule(ruleID uint, deletedBy uint) error {
	result := s.db.Delete(&model.Rule{}, ruleID)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return ErrRuleNotFound
	}

	// Remove from Redis
	s.redisClient.Del(fmt.Sprintf("waf:rules:%d", ruleID))

	return nil
}

// SyncAllRulesToRedis syncs all enabled rules to Redis cache
func (s *RuleService) SyncAllRulesToRedis() error {
	var rules []model.Rule
	result := s.db.Where("enabled = ?", true).Find(&rules)
	if result.Error != nil {
		return result.Error
	}

	for _, rule := range rules {
		s.syncRuleToRedis(&rule)
	}

	logger.Info(fmt.Sprintf("Synced %d rules to Redis", len(rules)))
	return nil
}

// syncRuleToRedis syncs a single rule to Redis
func (s *RuleService) syncRuleToRedis(rule *model.Rule) {
	redisKey := fmt.Sprintf("waf:rules:%d", rule.ID)

	ruleJSON, err := json.Marshal(rule)
	if err != nil {
		logger.Error("Failed to marshal rule for Redis:", err)
		return
	}

	s.redisClient.Set(redisKey, string(ruleJSON), 0)
}

// isValidRuleType checks if the provided rule type is valid
func isValidRuleType(ruleType string) bool {
	validTypes := []string{
		model.RuleTypes.SQLInjection,
		model.RuleTypes.XSS,
		model.RuleTypes.CCAttack,
		model.RuleTypes.PathTraversal,
		model.RuleTypes.CommandInjection,
		model.RuleTypes.SSIInjection,
		model.RuleTypes.XXEInjection,
		model.RuleTypes.CustomRegex,
	}

	for _, valid := range validTypes {
		if ruleType == valid {
			return true
		}
	}
	return false
}

// isValidAction checks if the provided action is valid
func isValidAction(action string) bool {
	return action == model.RuleActions.Deny ||
		action == model.RuleActions.Allow ||
		action == model.RuleActions.LogOnly
}
