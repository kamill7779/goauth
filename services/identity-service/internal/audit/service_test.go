package audit

import (
	"context"
	"testing"

	"example.com/identity-service/internal/config"
	"example.com/identity-service/internal/store"
)

func newTestService(t *testing.T) (*Service, *store.User) {
	t.Helper()

	db, err := store.OpenDB(config.Config{})
	if err != nil {
		t.Fatalf("store.OpenDB() error = %v", err)
	}
	if err := store.AutoMigrate(db); err != nil {
		t.Fatalf("store.AutoMigrate() error = %v", err)
	}

	user := &store.User{
		Email:        "actor@example.com",
		DisplayName:  "Actor",
		PasswordHash: "hash",
		Status:       store.UserStatusActive,
	}
	if err := db.Create(user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}

	return NewService(db), user
}

func TestRecordPersistsAuditLog(t *testing.T) {
	service, user := newTestService(t)

	if err := service.Record(context.Background(), Entry{
		ActorUserID: user.ID,
		Action:      ActionLogin,
		TargetType:  TargetTypeUser,
		TargetID:    "1",
		Metadata: map[string]any{
			"source": "password",
		},
	}); err != nil {
		t.Fatalf("Record() error = %v", err)
	}

	var logs []store.AuditLog
	if err := service.db.Order("id asc").Find(&logs).Error; err != nil {
		t.Fatalf("load audit logs: %v", err)
	}
	if len(logs) != 1 {
		t.Fatalf("audit log count = %d, want 1", len(logs))
	}
	if logs[0].Action != ActionLogin {
		t.Fatalf("action = %q, want %q", logs[0].Action, ActionLogin)
	}
}
