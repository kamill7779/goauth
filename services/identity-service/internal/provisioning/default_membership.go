// Package provisioning implements automatic tenant membership assignment.
// The DefaultMembershipPolicy grants membership to configured tenants at
// user creation time (both email registration and external IdP first login).
package provisioning

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"goauth/services/identity-service/internal/audit"
	"goauth/services/identity-service/internal/store"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var ErrDefaultTenantNotFound = errors.New("default member tenant not found")

// DefaultMembershipPolicy adds new users to a configured set of tenants at registration time.
type DefaultMembershipPolicy struct {
	tenantSlugs []string
}

// NewDefaultMembershipPolicy returns a policy that assigns membership in the given tenants.
//
// Call chain: wire → NewDefaultMembershipPolicy → normalizeSlugs
func NewDefaultMembershipPolicy(tenantSlugs []string) *DefaultMembershipPolicy {
	return &DefaultMembershipPolicy{tenantSlugs: normalizeSlugs(tenantSlugs)}
}

// Apply inserts tenant-member rows for every configured tenant slug, skipping duplicates.
// Returns the newly-created memberships (idempotent via ON CONFLICT DO NOTHING).
//
// Call chain: registration handler → Apply → gorm.DB.Create (ON CONFLICT DO NOTHING)
func (p *DefaultMembershipPolicy) Apply(ctx context.Context, db *gorm.DB, userID int64) ([]store.TenantMember, error) {
	if p == nil || len(p.tenantSlugs) == 0 || userID == 0 {
		return nil, nil
	}

	var tenants []store.Tenant
	if err := db.WithContext(ctx).
		Where("slug IN ? AND status = ?", p.tenantSlugs, store.TenantStatusActive).
		Find(&tenants).Error; err != nil {
		return nil, err
	}

	tenantsBySlug := make(map[string]store.Tenant, len(tenants))
	for _, tenant := range tenants {
		tenantsBySlug[tenant.Slug] = tenant
	}
	missing := make([]string, 0)
	for _, slug := range p.tenantSlugs {
		if _, ok := tenantsBySlug[slug]; !ok {
			missing = append(missing, slug)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return nil, fmt.Errorf("%w: %s", ErrDefaultTenantNotFound, strings.Join(missing, ","))
	}

	created := make([]store.TenantMember, 0, len(p.tenantSlugs))
	for _, slug := range p.tenantSlugs {
		tenant := tenantsBySlug[slug]
		member := store.TenantMember{
			TenantID: tenant.ID,
			UserID:   userID,
			Status:   store.MemberStatusActive,
		}
		result := db.WithContext(ctx).
			Clauses(clause.OnConflict{DoNothing: true}).
			Create(&member)
		if result.Error != nil {
			return nil, result.Error
		}
		if result.RowsAffected > 0 {
			created = append(created, member)
		}
	}
	return created, nil
}

// RecordMembershipAudits writes an audit entry for each newly-created tenant membership.
//
// Call chain: registration handler → RecordMembershipAudits → audit.Recorder.Record
func RecordMembershipAudits(ctx context.Context, recorder audit.Recorder, members []store.TenantMember) error {
	if recorder == nil {
		recorder = audit.NoopRecorder{}
	}
	for _, member := range members {
		if err := recorder.Record(ctx, audit.Entry{
			ActorUserID: 0,
			TenantID:    member.TenantID,
			Action:      audit.ActionTenantMembershipAdded,
			TargetType:  audit.TargetTypeTenantMember,
			TargetID:    strconv.FormatInt(member.ID, 10),
			Metadata: map[string]any{
				"user_id": member.UserID,
				"source":  "default_membership_policy",
			},
		}); err != nil {
			return err
		}
	}
	return nil
}

// normalizeSlugs deduplicates, trims whitespace, and drops empty entries.
//
// Call chain: NewDefaultMembershipPolicy → normalizeSlugs
func normalizeSlugs(slugs []string) []string {
	if len(slugs) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(slugs))
	result := make([]string, 0, len(slugs))
	for _, slug := range slugs {
		trimmed := strings.TrimSpace(slug)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		result = append(result, trimmed)
	}
	return result
}
