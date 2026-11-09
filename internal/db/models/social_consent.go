package models

import "time"

// SocialConsent records a consumed signed-cookie nonce until its expiry.
type SocialConsent struct {
	Token     string    `gorm:"primaryKey;size:64"`
	ExpiresAt time.Time `gorm:"index;not null"`
}
