package service

import (
	"fmt"
	"net"
	"strings"
)

// MaskingService handles PII data masking for privacy protection
type MaskingService struct{}

// NewMaskingService creates a new MaskingService instance
func NewMaskingService() *MaskingService {
	return &MaskingService{}
}

// MaskField masks a field value based on its name pattern
func (m *MaskingService) MaskField(fieldName, value interface{}) string {
	if value == nil {
		return ""
	}

	strVal, ok := value.(string)
	if !ok {
		strVal = fmt.Sprintf("%v", value)
	}

	lowerName := strings.ToLower(fieldName)

	switch {
	case m.isCreditCardField(lowerName):
		return m.MaskCreditCard(strVal)
	case m.isIDCardField(lowerName):
		return m.MaskIDNumber(strVal)
	case m.isPhoneField(lowerName):
		return m.MaskPhone(strVal)
	case m.isEmailField(lowerName):
		return m.MaskEmail(strVal)
	case m.isPasswordField(lowerName), m.isSecretField(lowerName), m.isTokenField(lowerName), m.isKeyField(lowerName):
		return "[REDACTED]"
	default:
		// Truncate long values
		if len(strVal) > 200 {
			return strVal[:200] + "...[TRUNCATED]"
		}
		return strVal
	}
}

// MaskTable recursively masks all fields in a map or slice
func (m *MaskingService) MaskTable(data interface{}) interface{} {
	switch v := data.(type) {
	case map[string]interface{}:
		masked := make(map[string]interface{})
		for key, val := range v {
			masked[key] = m.MaskField(key, val)
		}
		return masked
	case []interface{}:
		masked := make([]interface{}, len(v))
		for i, item := range v {
			masked[i] = m.MaskTable(item)
		}
		return masked
	default:
		return data
	}
}

// MaskCreditCard masks credit card number: 4111111111111111 -> 4111****1111
func (m *MaskingService) MaskCreditCard(number string) string {
	cleaned := strings.ReplaceAll(strings.ReplaceAll(number, " ", ""), "-", "")

	if len(cleaned) < 8 {
		return strings.Repeat("*", len(cleaned))
	}

	visibleStart := min(4, len(cleaned)-4)
	visibleEnd := min(4, len(cleaned)-visibleStart)

	return cleaned[:visibleStart] +
		strings.Repeat("*", len(cleaned)-visibleStart-visibleEnd) +
		cleaned[len(cleaned)-visibleEnd:]
}

// MaskIDNumber masks ID number keeping first 3 and last 4 digits
func (m *MaskingService) MaskIDNumber(id string) string {
	cleaned := strings.ReplaceAll(id, " ", "")

	if len(cleaned) <= 7 {
		return strings.Repeat("*", len(cleaned))
	}

	return cleaned[:3] + strings.Repeat("*", len(cleaned)-7) + cleaned[len(cleaned)-4:]
}

// MaskPhone masks phone number keeping first 3 and last 4 digits
func (m *MaskingService) MaskPhone(phone string) string {
	cleaned := strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(phone, " ", ""), "-", ""), "+", "")

	if len(cleaned) <= 7 {
		return strings.Repeat("*", len(cleaned))
	}

	return cleaned[:3] + strings.Repeat("*", len(cleaned)-7) + cleaned[len(cleaned)-4:]
}

// MaskEmail masks email address: user@example.com -> u***@example.com
func (m *MaskingService) MaskEmail(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return "***@***.***"
	}

	username, domain := parts[0], parts[1]

	if len(username) <= 1 {
		return "*@" + domain
	}

	return username[:1] + strings.Repeat("*", len(username)-1) + "@" + domain
}

// Field type detection helpers
func (m *MaskingService) isCreditCardField(name string) bool {
	return strings.Contains(name, "card") ||
		strings.Contains(name, "credit") ||
		strings.Contains(name, "cc_num") ||
		strings.Contains(name, "ccnum")
}

func (m *MaskingService) isIDCardField(name string) bool {
	return strings.Contains(name, "id_card") ||
		strings.Contains(name, "ssn") ||
		strings.Contains(name, "identity") ||
		strings.Contains(name, "id_number")
}

func (m *MaskingService) isPhoneField(name string) bool {
	return strings.Contains(name, "phone") ||
		strings.Contains(name, "mobile") ||
		strings.Contains(name, "tel")
}

func (m *MaskingService) isEmailField(name string) bool {
	return strings.Contains(name, "email") ||
		strings.Contains(name, "mail")
}

func (m *MaskingService) isPasswordField(name string) bool {
	return strings.Contains(name, "pass")
}

func (m *MaskingService) isSecretField(name string) bool {
	return strings.Contains(name, "secret")
}

func (m *MaskingService) isTokenField(name string) bool {
	return strings.Contains(name, "token")
}

func (m *MaskingService) isKeyField(name string) bool {
	return strings.Contains(name, "key") && !strings.Contains(name, "foreign")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// IsValidIP validates IPv4/IPv6 address format
func IsValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}
