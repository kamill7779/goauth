package user

import (
	"context"
	"errors"
	"strings"
	"time"

	"goauth/services/identity-service/internal/audit"
	"goauth/services/identity-service/internal/auth"
	"goauth/services/identity-service/internal/store"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var ErrProtectedUser = errors.New("protected user cannot be disabled")

var protectedRoleCodes = []string{"root", "system-admin", "system_admin"}

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

type ListUsersInput struct {
	Search   string
	Status   string
	Sort     string
	TenantID int64
	RoleID   int64
	Page     int
	PageSize int
}

type ListUsersResult struct {
	Users    []store.User
	Total    int64
	Page     int
	PageSize int
}

type BootstrapAdminInput struct {
	Email       string
	DisplayName string
	Password    string
	RoleCode    string
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

func (s *Service) ListUsersPage(ctx context.Context, input ListUsersInput) (*ListUsersResult, error) {
	page := input.Page
	if page < 1 {
		page = 1
	}
	pageSize := input.PageSize
	if pageSize < 1 {
		pageSize = 20
	}
	if pageSize > 100 {
		pageSize = 100
	}

	query := s.db.WithContext(ctx).Model(&store.User{})
	if search := strings.ToLower(strings.TrimSpace(input.Search)); search != "" {
		like := "%" + search + "%"
		query = query.Where("LOWER(email) LIKE ? OR LOWER(display_name) LIKE ?", like, like)
	}
	if status := strings.TrimSpace(input.Status); status != "" {
		query = query.Where("status = ?", status)
	}
	if input.TenantID > 0 {
		query = query.Where(
			"EXISTS (SELECT 1 FROM tenant_members tm WHERE tm.user_id = users.id AND tm.tenant_id = ? AND tm.deleted_at IS NULL)",
			input.TenantID,
		)
	}
	if input.RoleID > 0 {
		query = query.Where(
			`EXISTS (
				SELECT 1
				FROM tenant_members tm
				JOIN member_roles mr ON mr.member_id = tm.id
				WHERE tm.user_id = users.id AND mr.role_id = ? AND tm.deleted_at IS NULL
			)`,
			input.RoleID,
		)
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, err
	}

	var users []store.User
	if err := query.
		Order(userListOrder(input.Sort)).
		Offset((page - 1) * pageSize).
		Limit(pageSize).
		Find(&users).Error; err != nil {
		return nil, err
	}

	return &ListUsersResult{
		Users:    users,
		Total:    total,
		Page:     page,
		PageSize: pageSize,
	}, nil
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

func (s *Service) EnsureBootstrapAdmin(ctx context.Context, input BootstrapAdminInput) (*store.User, error) {
	email := normalizeEmail(input.Email)
	if email == "" {
		return nil, errors.New("bootstrap admin email is required")
	}
	if strings.TrimSpace(input.Password) == "" {
		return nil, errors.New("bootstrap admin password is required")
	}

	roleCode := strings.TrimSpace(input.RoleCode)
	if roleCode == "" {
		roleCode = "root"
	}

	displayName := strings.TrimSpace(input.DisplayName)
	if displayName == "" {
		displayName = email
	}

	var record store.User
	now := time.Now().UTC()
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		err := tx.Where("email = ?", email).First(&record).Error
		switch {
		case errors.Is(err, gorm.ErrRecordNotFound):
			hash, err := auth.HashPassword(input.Password)
			if err != nil {
				return err
			}
			record = store.User{
				Email:           email,
				DisplayName:     displayName,
				PasswordHash:    hash,
				Status:          store.UserStatusActive,
				EmailVerifiedAt: &now,
			}
			if err := tx.Create(&record).Error; err != nil {
				return err
			}
		case err != nil:
			return err
		default:
			passwordChanged := auth.CheckPassword(record.PasswordHash, input.Password) != nil
			reactivated := record.Status != store.UserStatusActive
			needsEmailVerification := record.EmailVerifiedAt == nil
			displayNameChanged := record.DisplayName != displayName

			updates := map[string]any{}
			if displayNameChanged {
				updates["display_name"] = displayName
			}
			if passwordChanged {
				hash, err := auth.HashPassword(input.Password)
				if err != nil {
					return err
				}
				updates["password_hash"] = hash
			}
			if reactivated {
				updates["status"] = store.UserStatusActive
			}
			if needsEmailVerification {
				updates["email_verified_at"] = now
			}
			if reactivated || passwordChanged {
				updates["token_version"] = gorm.Expr("token_version + 1")
			}
			if len(updates) > 0 {
				updates["updated_at"] = now
				if err := tx.Model(&store.User{}).Where("id = ?", record.ID).Updates(updates).Error; err != nil {
					return err
				}
				if err := tx.First(&record, record.ID).Error; err != nil {
					return err
				}
			}
		}

		bootstrapService := &Service{
			db:    tx,
			audit: s.audit,
		}
		return bootstrapService.MarkSystemUser(ctx, record.ID, roleCode)
	})
	if err != nil {
		return nil, err
	}

	return &record, nil
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
		if err := tx.Clauses(clause.OnConflict{
			Columns: []clause.Column{{Name: "tenant_id"}, {Name: "user_id"}},
			DoUpdates: clause.Assignments(map[string]any{
				"status":     store.MemberStatusActive,
				"deleted_at": nil,
			}),
		}).Create(&member).Error; err != nil {
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
	var count int64
	err := s.db.WithContext(ctx).
		Table("tenant_members AS tm").
		Joins("JOIN users AS u ON u.id = tm.user_id AND u.status = ? AND u.deleted_at IS NULL", store.UserStatusActive).
		Joins("JOIN tenants AS t ON t.id = tm.tenant_id AND t.status = ? AND t.deleted_at IS NULL", store.TenantStatusActive).
		Joins("JOIN member_roles AS mr ON mr.member_id = tm.id").
		Joins("JOIN roles AS r ON r.id = mr.role_id AND r.tenant_id = tm.tenant_id").
		Where("tm.user_id = ? AND tm.status = ? AND tm.deleted_at IS NULL", id, store.MemberStatusActive).
		Where("r.is_system = ? OR r.code IN ?", true, protectedRoleCodes).
		Count(&count).Error
	if err != nil {
		return false, err
	}

	return count > 0, nil
}

func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func userListOrder(sort string) string {
	switch strings.TrimSpace(sort) {
	case "email_asc":
		return "email ASC, id ASC"
	case "email_desc":
		return "email DESC, id DESC"
	case "created_at_asc":
		return "created_at ASC, id ASC"
	case "updated_at_desc":
		return "updated_at DESC, id DESC"
	case "updated_at_asc":
		return "updated_at ASC, id ASC"
	case "id_asc":
		return "id ASC"
	case "id_desc":
		return "id DESC"
	default:
		return "created_at DESC, id DESC"
	}
}
