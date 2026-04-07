package service

import (
	"errors"
	"sync"
	"time"
)

var (
	ErrCaptchaNotFound      = errors.New("captcha not found or expired")
	ErrCaptchaAlreadyUsed   = errors.New("captcha already verified")
	ErrCaptchaTokenInvalid  = errors.New("invalid captcha token")
	ErrVerificationNotFound = errors.New("verification record not found")
)

type CaptchaService struct {
	mu            sync.RWMutex
	captchas      map[string]*Captcha
	verifications map[string]*Verification
}

type Captcha struct {
	Token       string
	ClientIP    string
	Verified    bool
	CreatedAt   time.Time
	ExpiresAt   time.Time
	RedirectURL string
}

type Verification struct {
	Token     string
	ClientIP  string
	ExpiresAt time.Time
}

const CaptchaValidityDuration = 24 * time.Hour

func NewCaptchaService() *CaptchaService {
	svc := &CaptchaService{
		captchas:      make(map[string]*Captcha),
		verifications: make(map[string]*Verification),
	}
	go svc.cleanupExpired()
	return svc
}

func (s *CaptchaService) cleanupExpired() {
	ticker := time.NewTicker(5 * time.Minute)
	for range ticker.C {
		s.mu.Lock()
		now := time.Now()
		for token, captcha := range s.captchas {
			if now.After(captcha.ExpiresAt) {
				delete(s.captchas, token)
			}
		}
		for ip, verification := range s.verifications {
			if now.After(verification.ExpiresAt) {
				delete(s.verifications, ip)
			}
		}
		s.mu.Unlock()
	}
}

func (s *CaptchaService) GenerateCaptcha(clientIP, redirectURL string) (string, string) {
	token := generateToken()
	verifyToken := generateToken()

	s.mu.Lock()
	defer s.mu.Unlock()

	s.captchas[token] = &Captcha{
		Token:       token,
		ClientIP:    clientIP,
		Verified:    false,
		CreatedAt:   time.Now(),
		ExpiresAt:   time.Now().Add(10 * time.Minute),
		RedirectURL: redirectURL,
	}

	s.verifications[clientIP] = &Verification{
		Token:     verifyToken,
		ClientIP:  clientIP,
		ExpiresAt: time.Now().Add(CaptchaValidityDuration),
	}

	return token, verifyToken
}

func (s *CaptchaService) VerifyCaptcha(token, clientIP string) (string, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	captcha, exists := s.captchas[token]
	if !exists {
		return "", "", ErrCaptchaNotFound
	}

	if time.Now().After(captcha.ExpiresAt) {
		delete(s.captchas, token)
		return "", "", ErrCaptchaNotFound
	}

	if captcha.Verified {
		return "", "", ErrCaptchaAlreadyUsed
	}

	if captcha.ClientIP != "" && captcha.ClientIP != clientIP {
		return "", "", ErrCaptchaTokenInvalid
	}

	captcha.Verified = true
	redirectURL := captcha.RedirectURL

	verification := s.verifications[clientIP]
	verifyToken := ""
	if verification != nil {
		verifyToken = verification.Token
		verification.ExpiresAt = time.Now().Add(CaptchaValidityDuration)
	} else {
		verifyToken = generateToken()
		s.verifications[clientIP] = &Verification{
			Token:     verifyToken,
			ClientIP:  clientIP,
			ExpiresAt: time.Now().Add(CaptchaValidityDuration),
		}
	}

	delete(s.captchas, token)

	return redirectURL, verifyToken, nil
}

func (s *CaptchaService) GetVerificationToken(clientIP string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	verification, exists := s.verifications[clientIP]
	if !exists {
		return "", ErrVerificationNotFound
	}

	if time.Now().After(verification.ExpiresAt) {
		return "", ErrVerificationNotFound
	}

	return verification.Token, nil
}

func (s *CaptchaService) IsVerified(clientIP string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	verification, exists := s.verifications[clientIP]
	if !exists {
		return false
	}

	return time.Now().Before(verification.ExpiresAt)
}

func generateToken() string {
	return time.Now().Format("20060102150405") + randomString(16)
}

func randomString(length int) string {
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	result := make([]byte, length)
	for i := range result {
		result[i] = chars[time.Now().UnixNano()%int64(len(chars))]
	}
	return string(result)
}
