package user

import (
	"context"
	"errors"
	"strings"

	"goauth/services/identity-service/internal/audit"
	"goauth/services/identity-service/internal/auth"
	"goauth/services/identity-service/internal/store"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var ErrProtectedUser = errors.New("protected user cannot be disabled")

type Service struct {
	db    *gorm.DB
	audit audit.Recorder
}

type CreateUserInput struct {
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
	Password    string `json:"password"`
	AvatarURL   string `json:"avatar_url"`
	Status      string `json:"status"`
}

type UpdateUserInput struct {
	Email       *string `json:"email"`
	DisplayName *string `json:"display_name"`
	AvatarURL   *string `json:"avatar_url"`
}

func NewService(db *gorm.DB, recorder audit.Recorder) *Service {
	if recorder == nil {
		recorder = audit.NoopRecorder{}
	}
	return &Service{
		db:    db,
		audit: recorder,
	}
}

func (s *Service) ListUsers(ctx context.Context) ([]store.User, error) {
	var users []store.User
	err := s.db.WithContext(ctx).Order("id ASC").Find(&users).Error
	return users, err
}

func (s *Service) GetUser(ctx context.Context, id int64) (*store.User, error) {
	var user store.User
	if err := s.db.WithContext(ctx).First(&user, id).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

func (s *Service) CreateUser(ctx context.Context, input CreateUserInput) (*store.User, error) {
	hash, err := auth.HashPassword(input.Password)
	if err != nil {
		return nil, err
	}

	status := input.Status
	if status == "" {
		status = store.UserStatusActive
	}

	displayName := strings.TrimSpace(input.DisplayName)
	email := normalizeEmail(input.Email)
	if displayName == "" {
		displayName = email
	}

	record := &store.User{
		Email:        email,
		DisplayName:  displayName,
		PasswordHash: hash,
		AvatarURL:    strings.TrimSpace(input.AvatarURL),
		Status:       status,
	}
	if err := s.db.WithContext(ctx).Create(record).Error; err != nil {
		return nil, err
	}

	_ = s.audit.Record(ctx, audit.Entry{
		Action:     audit.ActionUserCreated,
		TargetType: audit.TargetTypeUser,
		TargetID:   audit.UserTargetID(record.ID),
		Metadata: map[string]any{
			"email": record.Email,
		},
	})

	return record, nil
}

func (s *Service) UpdateUser(ctx context.Context, id int64, input UpdateUserInput) (*store.User, error) {
	updates := map[string]any{}
	if input.Email != nil {
		updates["email"] = normalizeEmail(*input.Email)
	}
	if input.DisplayName != nil {
		updates["display_name"] = strings.TrimSpace(*input.DisplayName)
	}
	if input.AvatarURL != nil {
		updates["avatar_url"] = strings.TrimSpace(*input.AvatarURL)
	}
	if len(updates) > 0 {
		if err := s.db.WithContext(ctx).Model(&store.User{}).Where("id = ?", id).Updates(updates).Error; err != nil {
			return nil, err
		}
	}

	record, err := s.GetUser(ctx, id)
	if err != nil {
		return nil, err
	}

	_ = s.audit.Record(ctx, audit.Entry{
		Action:     audit.ActionUserUpdated,
		TargetType: audit.TargetTypeUser,
		TargetID:   audit.UserTargetID(id),
	})

	return record, nil
}

func (s *Service) DisableUser(ctx context.Context, id int64) error {
	protected, err := s.isProtectedUser(ctx, id)
	if err != nil {
		return err
	}
	if protected {
		return ErrProtectedUser
	}

	if err := s.db.WithContext(ctx).Model(&store.User{}).Where("id = ?", id).Update("status", store.UserStatusDisabled).Error; err != nil {
		return err
	}

	return s.audit.Record(ctx, audit.Entry{
		Action:     audit.ActionUserDisabled,
		TargetType: audit.TargetTypeUser,
		TargetID:   audit.UserTargetID(id),
	})
}

func (s *Service) EnableUser(ctx context.Context, id int64) error {
	if err := s.db.WithContext(ctx).Model(&store.User{}).Where("id = ?", id).Update("status", store.UserStatusActive).Error; err != nil {
		return err
	}

	return s.audit.Record(ctx, audit.Entry{
		Action:     audit.ActionUserEnabled,
		TargetType: audit.TargetTypeUser,
		TargetID:   audit.UserTargetID(id),
	})
}

func (s *Service) ResetPassword(ctx context.Context, id int64, password string) error {
	hash, err := auth.HashPassword(password)
	if err != nil {
		return err
	}

	if err := s.db.WithContext(ctx).Model(&store.User{}).Where("id = ?", id).Updates(map[string]any{
		"password_hash": hash,
		"token_version": gorm.Expr("token_version + 1"),
	}).Error; err != nil {
		return err
	}

	return s.audit.Record(ctx, audit.Entry{
		Action:     audit.ActionPasswordReset,
		TargetType: audit.TargetTypeUser,
		TargetID:   audit.UserTargetID(id),
		Metadata: map[string]any{
			"source": "admin",
		},
	})
}

func (s *Service) MarkSystemUser(ctx context.Context, userID int64, roleCode string) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		tenantRecord := store.Tenant{
			Slug:   "system",
			Name:   "System",
			Status: store.TenantStatusActive,
		}
		if err := tx.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "slug"}},
			DoUpdates: clause.AssignmentColumns([]string{"name", "status"}),
		}).Create(&tenantRecord).Error; err != nil {
			return err
		}
		if tenantRecord.ID == 0 {
			if err := tx.Where("slug = ?", "system").First(&tenantRecord).Error; err != nil {
				return err
			}
		}

		member := store.TenantMember{
			TenantID: tenantRecord.ID,
			UserID:   userID,
			Status:   store.MemberStatusActive,
		}
		if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&member).Error; err != nil {
			return err
		}
		if member.ID == 0 {
			if err := tx.Where("tenant_id = ? AND user_id = ?", tenantRecord.ID, userID).First(&member).Error; err != nil {
				return err
			}
		}

		role := store.Role{
			TenantID: tenantRecord.ID,
			Name:     strings.ToUpper(roleCode),
			Code:     roleCode,
			IsSystem: true,
		}
		if err := tx.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "tenant_id"}, {Name: "code"}},
			DoUpdates: clause.AssignmentColumns([]string{"name", "is_system"}),
		}).Create(&role).Error; err != nil {
			return err
		}
		if role.ID == 0 {
			if err := tx.Where("tenant_id = ? AND code = ?", tenantRecord.ID, roleCode).First(&role).Error; err != nil {
				return err
			}
		}

		memberRole := store.MemberRole{
			MemberID: member.ID,
			RoleID:   role.ID,
		}
		return tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&memberRole).Error
	})
}

func (s *Service) isProtectedUser(ctx context.Context, id int64) (bool, error) {
	var user store.User
	if err := s.db.WithContext(ctx).First(&user, id).Error; err != nil {
		return false, err
	}
	if strings.EqualFold(user.Email, "root@example.com") || strings.HasPrefix(strings.ToLower(user.Email), "root@") {
		return true, nil
	}

	var count int64
	err := s.db.WithContext(ctx).
		Table("roles").
		Joins("JOIN member_roles ON member_roles.role_id = roles.id").
		Joins("JOIN tenant_members ON tenant_members.id = member_roles.member_id").
		Where("tenant_members.user_id = ?", id).
		Where("roles.is_system = ? OR roles.code IN ?", true, []string{"root", "system-admin", "system_admin"}).
		Count(&count).Error
	if err != nil {
		return false, err
	}

	return count > 0, nil
}

func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}
