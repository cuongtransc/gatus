package security

import (
	"encoding/base64"
	"time"
)

// DefaultBasicSessionTTL is the default lifetime of a session created through the login form
const DefaultBasicSessionTTL = 8 * time.Hour

// BasicConfig is the configuration for Basic authentication
type BasicConfig struct {
	// Username is the name which will need to be used for a successful authentication
	Username string `yaml:"username"`

	// PasswordBcryptHashBase64Encoded is the base64 encoded string of the Bcrypt hash of the password to use to
	// authenticate using basic auth.
	PasswordBcryptHashBase64Encoded string `yaml:"password-bcrypt-base64"`

	// LoginForm enables a username/password login form (with session cookie) instead of the browser's Basic Auth prompt
	LoginForm bool `yaml:"login-form,omitempty"`

	// SessionTTL is the lifetime of a login form session, e.g. 8h. Defaults to 8 hours
	SessionTTL time.Duration `yaml:"session-ttl,omitempty"`
}

// decodedPasswordHash returns the base64 (URL encoding) decoded bcrypt hash
func (c *BasicConfig) decodedPasswordHash() ([]byte, error) {
	if len(c.PasswordBcryptHashBase64Encoded) == 0 {
		return nil, nil
	}
	return base64.URLEncoding.DecodeString(c.PasswordBcryptHashBase64Encoded)
}

// isValid returns whether the basic security configuration is valid or not
func (c *BasicConfig) isValid() bool {
	return len(c.Username) > 0 && len(c.PasswordBcryptHashBase64Encoded) > 0
}
