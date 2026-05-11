package store

import (
	"fmt"
	"strings"

	"goauth/services/identity-service/internal/identity"

	"gorm.io/gorm"
)

const (
	usernameMaxLength = 64
)

func deriveUsernameBase(email string) string {
	return identity.UsernameFromEmail(email)
}

// deriveNicknameForUser returns the nickname to write when a caller did not
// supply one. It prefers an existing DisplayName, then the email local-part.
func deriveNicknameForUser(u *User) string {
	if u == nil {
		return ""
	}
	if name := strings.TrimSpace(u.DisplayName); name != "" {
		return name
	}
	if at := strings.Index(u.Email, "@"); at > 0 {
		local := strings.TrimSpace(u.Email[:at])
		if local != "" {
			return strings.ToLower(local)
		}
	}
	return ""
}

// ensureUniqueUsername resolves collisions by appending an incrementing
// numeric suffix while staying inside usernameMaxLength. Pass excludeID > 0
// to ignore an existing row (useful when updating the row currently being
// backfilled).
func ensureUniqueUsername(tx *gorm.DB, base string, excludeID int64) string {
	if base == "" {
		base = "user"
	}
	candidate := base
	for suffix := 2; suffix < 10_000; suffix++ {
		exists, err := usernameTaken(tx, candidate, excludeID)
		if err != nil || !exists {
			return candidate
		}
		suffixStr := fmt.Sprintf("%d", suffix)
		room := usernameMaxLength - len(suffixStr)
		if room < 1 {
			room = 1
		}
		head := base
		if len(head) > room {
			head = head[:room]
		}
		candidate = head + suffixStr
	}
	return candidate
}

func usernameTaken(tx *gorm.DB, candidate string, excludeID int64) (bool, error) {
	if tx == nil {
		return false, nil
	}
	q := tx.Session(&gorm.Session{NewDB: true}).Table("users").Where("username = ?", candidate)
	if excludeID > 0 {
		q = q.Where("id <> ?", excludeID)
	}
	var count int64
	if err := q.Count(&count).Error; err != nil {
		return false, err
	}
	return count > 0, nil
}

// backfillUserIdentityFields fills empty username/nickname columns for rows
// that pre-date the new schema. Deconfliction produces unique values so the
// unique index can be created afterward.
func backfillUserIdentityFields(db *gorm.DB) error {
	type legacyRow struct {
		ID          int64
		Email       string
		DisplayName string
	}

	var rows []legacyRow
	if err := db.
		Table("users").
		Select("id, email, display_name").
		Where("username = '' OR username IS NULL").
		Order("id ASC").
		Find(&rows).Error; err != nil {
		return fmt.Errorf("load legacy users for backfill: %w", err)
	}
	if len(rows) == 0 {
		return nil
	}

	for _, row := range rows {
		base := deriveUsernameBase(row.Email)
		if base == "" {
			base = fmt.Sprintf("user%d", row.ID)
		}
		username := ensureUniqueUsername(db, base, row.ID)

		nickname := strings.TrimSpace(row.DisplayName)
		if nickname == "" {
			if at := strings.Index(row.Email, "@"); at > 0 {
				nickname = strings.ToLower(strings.TrimSpace(row.Email[:at]))
			}
		}
		if nickname == "" {
			nickname = username
		}

		if err := db.Exec(
			`UPDATE users SET username = ?, nickname = ? WHERE id = ?`,
			username, nickname, row.ID,
		).Error; err != nil {
			return fmt.Errorf("backfill user %d: %w", row.ID, err)
		}
	}
	return nil
}
