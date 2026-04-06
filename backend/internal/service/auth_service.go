package service

import (
	"errors"
	"time"

	"github.com/waf-project/backend/internal/model"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// 认证服务错误定义
var (
	ErrUserNotFound       = errors.New("用户不存在")
	ErrInvalidCredentials = errors.New("用户名或密码错误")
	ErrUserAlreadyExists  = errors.New("用户已存在")
)

// AuthService - 认证服务，处理用户认证相关的业务逻辑
// 提供用户登录、注册、密码修改等功能
type AuthService struct {
	db *gorm.DB
}

// NewAuthService - 创建认证服务实例
func NewAuthService(db *gorm.DB) *AuthService {
	return &AuthService{db: db}
}

// LoginRequest - 登录请求结构体
type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// LoginResponse - 登录成功响应结构体
type LoginResponse struct {
	User         *model.User `json:"user"`
	AccessToken  string      `json:"access_token"`
	RefreshToken string      `json:"refresh_token"`
	ExpiresIn    int64       `json:"expires_in"` // 过期时间（秒）
}

// Authenticate - 验证用户凭据并返回登录响应
// 1. 根据用户名查找用户
// 2. 验证密码（bcrypt 比较）
// 3. 更新最后登录时间
// 4. 返回用户信息和 token
func (s *AuthService) Authenticate(req *LoginRequest) (*LoginResponse, error) {
	var user model.User

	result := s.db.Where("username = ? AND is_active = ?", req.Username, true).First(&user)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, ErrInvalidCredentials
		}
		return nil, result.Error
	}

	// 使用 bcrypt 验证密码
	err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password))
	if err != nil {
		return nil, ErrInvalidCredentials
	}

	// 更新最后登录时间
	now := time.Now()
	s.db.Model(&user).Update("last_login_at", now)
	user.LastLoginAt = &now

	// Token 生成由中间件处理
	return &LoginResponse{
		User:      &user,
		ExpiresIn: 86400, // 24 小时
	}, nil
}

// CreateUser - 创建新用户（用于初始管理员账户创建）
// 使用 bcrypt 对密码进行哈希加密（cost=12）
func (s *AuthService) CreateUser(username, password, role string) (*model.User, error) {
	// 检查用户名是否已存在
	var existingUser model.User
	result := s.db.Where("username = ?", username).First(&existingUser)
	if result.Error == nil {
		return nil, ErrUserAlreadyExists
	}
	if !errors.Is(result.Error, gorm.ErrRecordNotFound) {
		return nil, result.Error
	}

	// 使用 bcrypt 加密密码（cost=12，安全强度高）
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	user := model.User{
		Username:     username,
		PasswordHash: string(hashedPassword),
		Role:         role,
		IsActive:     true,
	}

	result = s.db.Create(&user)
	if result.Error != nil {
		return nil, result.Error
	}

	return &user, nil
}

// GetUserByID - 根据用户 ID 获取用户信息
func (s *AuthService) GetUserByID(userID uint) (*model.User, error) {
	var user model.User
	result := s.db.First(&user, userID)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, result.Error
	}
	return &user, nil
}

// ChangePassword - 修改用户密码
// 1. 验证旧密码
// 2. 使用 bcrypt 加密新密码
// 3. 更新数据库
func (s *AuthService) ChangePassword(userID uint, oldPassword, newPassword string) error {
	var user model.User
	result := s.db.First(&user, userID)
	if result.Error != nil {
		return result.Error
	}

	// 验证旧密码
	err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(oldPassword))
	if err != nil {
		return ErrInvalidCredentials
	}

	// bcrypt 加密新密码
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	// 更新密码
	return s.db.Model(&user).Update("password_hash", string(hashedPassword)).Error
}

// EnsureDefaultAdmin - 确保存在至少一个管理员账户
// 如果不存在，则创建默认管理员账户（admin / Admin@2024Secure!）
func (s *AuthService) EnsureDefaultAdmin() error {
	var count int64
	s.db.Model(&model.User{}).Where("role = ?", model.UserRoles.Admin).Count(&count)

	if count == 0 {
		_, err := s.CreateUser("admin", "Admin@2024Secure!", model.UserRoles.Admin)
		if err != nil {
			return err
		}
		logger.Info("默认管理员账户已创建: admin / Admin@2024Secure!")
	}

	return nil
}
