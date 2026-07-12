package db

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/ChamathDilshanC/VibeNet-backend/internal/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Group/invite errors surfaced to the API layer for precise status codes.
var (
	// ErrNotGroupMember is returned when the acting user does not belong to the group.
	ErrNotGroupMember = errors.New("not a member of this group")
	// ErrAlreadyGroupMember is returned when inviting a user who already belongs to the group.
	ErrAlreadyGroupMember = errors.New("user is already a member of this group")
	// ErrInviteNotPending is returned when accepting/declining an invite that was
	// already resolved (or never addressed to the acting user).
	ErrInviteNotPending = errors.New("invite is not pending for this user")
)

// GroupMemberInfo is a group member joined with the public profile fields the
// client renders (name resolution for bubbles, avatars in the member list).
type GroupMemberInfo struct {
	UserID      uuid.UUID `json:"user_id"`
	Username    string    `json:"username"`
	DisplayName string    `json:"display_name"`
	AvatarURL   *string   `json:"avatar_url,omitempty"`
	Role        string    `json:"role"`
}

// GroupWithMembers is a group plus its full member roster and the requesting
// user's own membership row (carrying their wrapped copy of the group key).
type GroupWithMembers struct {
	Group      models.Group
	Members    []GroupMemberInfo
	Membership models.GroupMember
}

// GroupInviteInfo is a pending invite joined with the context the invites UI
// shows: the group's name and the inviter's public profile.
type GroupInviteInfo struct {
	Invite          models.GroupInvite
	GroupName       string
	FromUsername    string
	FromDisplayName string
	FromAvatarURL   *string
}

// CreateGroupWithMembers creates a group and its initial member rows (the
// creator plus any directly-added contacts) in one transaction. Every member
// row must already carry its wrapped group key — the creator's client wraps
// the key for each member before calling the API.
func (r *PostgresRepo) CreateGroupWithMembers(
	ctx context.Context,
	name string,
	createdBy uuid.UUID,
	members []models.GroupMember,
) (*models.Group, error) {
	group := &models.Group{Name: name, CreatedBy: createdBy}
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(group).Error; err != nil {
			return fmt.Errorf("create group: %w", err)
		}
		for i := range members {
			members[i].GroupID = group.GroupID
		}
		if err := tx.Create(&members).Error; err != nil {
			return fmt.Errorf("create group members: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return group, nil
}

// GetGroupWithMembers loads a group, its member roster (joined with user
// profiles), and forUser's own membership row. Returns ErrNotGroupMember when
// forUser does not belong to the group — membership is also the access check.
func (r *PostgresRepo) GetGroupWithMembers(ctx context.Context, groupID, forUser uuid.UUID) (*GroupWithMembers, error) {
	var membership models.GroupMember
	err := r.db.WithContext(ctx).
		Where("group_id = ? AND user_id = ?", groupID, forUser).
		First(&membership).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotGroupMember
		}
		return nil, fmt.Errorf("lookup group membership: %w", err)
	}

	var group models.Group
	if err := r.db.WithContext(ctx).Where("group_id = ?", groupID).First(&group).Error; err != nil {
		return nil, fmt.Errorf("lookup group: %w", err)
	}

	members, err := r.listGroupMembers(ctx, groupID)
	if err != nil {
		return nil, err
	}
	return &GroupWithMembers{Group: group, Members: members, Membership: membership}, nil
}

// listGroupMembers returns a group's roster joined with public profile fields.
func (r *PostgresRepo) listGroupMembers(ctx context.Context, groupID uuid.UUID) ([]GroupMemberInfo, error) {
	var members []GroupMemberInfo
	err := r.db.WithContext(ctx).
		Table("group_members").
		Select("group_members.user_id, users.username, users.display_name, users.avatar_url, group_members.role").
		Joins("JOIN users ON users.user_id = group_members.user_id").
		Where("group_members.group_id = ?", groupID).
		Order("group_members.joined_at ASC").
		Scan(&members).Error
	if err != nil {
		return nil, fmt.Errorf("list group members: %w", err)
	}
	// Mirror displayNameOf's fallback so the client never renders an empty label.
	for i := range members {
		if members[i].DisplayName == "" {
			members[i].DisplayName = members[i].Username
		}
	}
	return members, nil
}

// ListGroupsForUser returns every group the user belongs to, newest first, each
// with its full roster and the user's own membership (wrapped key material).
func (r *PostgresRepo) ListGroupsForUser(ctx context.Context, userID uuid.UUID) ([]GroupWithMembers, error) {
	var memberships []models.GroupMember
	if err := r.db.WithContext(ctx).
		Where("user_id = ?", userID).
		Find(&memberships).Error; err != nil {
		return nil, fmt.Errorf("list group memberships: %w", err)
	}
	if len(memberships) == 0 {
		return []GroupWithMembers{}, nil
	}

	groupIDs := make([]uuid.UUID, 0, len(memberships))
	membershipByGroup := make(map[uuid.UUID]models.GroupMember, len(memberships))
	for _, m := range memberships {
		groupIDs = append(groupIDs, m.GroupID)
		membershipByGroup[m.GroupID] = m
	}

	var groups []models.Group
	if err := r.db.WithContext(ctx).
		Where("group_id IN ?", groupIDs).
		Order("created_at DESC").
		Find(&groups).Error; err != nil {
		return nil, fmt.Errorf("list groups: %w", err)
	}

	result := make([]GroupWithMembers, 0, len(groups))
	for _, g := range groups {
		members, err := r.listGroupMembers(ctx, g.GroupID)
		if err != nil {
			return nil, err
		}
		result = append(result, GroupWithMembers{
			Group:      g,
			Members:    members,
			Membership: membershipByGroup[g.GroupID],
		})
	}
	return result, nil
}

// GetGroupMemberIDs returns the user IDs of everyone in the group — the
// broadcast fan-out list the WebSocket hub routes group frames to.
func (r *PostgresRepo) GetGroupMemberIDs(ctx context.Context, groupID uuid.UUID) ([]uuid.UUID, error) {
	var ids []uuid.UUID
	err := r.db.WithContext(ctx).
		Model(&models.GroupMember{}).
		Where("group_id = ?", groupID).
		Pluck("user_id", &ids).Error
	if err != nil {
		return nil, fmt.Errorf("list group member ids: %w", err)
	}
	return ids, nil
}

// IsGroupMember reports whether the user belongs to the group.
func (r *PostgresRepo) IsGroupMember(ctx context.Context, groupID, userID uuid.UUID) (bool, error) {
	var count int64
	err := r.db.WithContext(ctx).
		Model(&models.GroupMember{}).
		Where("group_id = ? AND user_id = ?", groupID, userID).
		Count(&count).Error
	if err != nil {
		return false, fmt.Errorf("check group membership: %w", err)
	}
	return count > 0, nil
}

// CreateInvite records a pending invitation, carrying the group key the
// inviter's client wrapped for the invitee. The caller has already verified
// the inviter's own membership and that the target isn't a member.
//
// Re-inviting someone with an unresolved (or declined) invite refreshes that
// row back to pending with the new key material rather than inserting a
// duplicate — the unique (group_id, to_user) index enforces one row per target.
func (r *PostgresRepo) CreateInvite(ctx context.Context, invite *models.GroupInvite) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var existing models.GroupInvite
		err := tx.Where("group_id = ? AND to_user = ?", invite.GroupID, invite.ToUser).
			First(&existing).Error
		if err == nil {
			if existing.Status == models.InviteStatusAccepted {
				// They already joined through this invite; the membership check
				// upstream should have caught it, but guard the race anyway.
				return ErrAlreadyGroupMember
			}
			result := tx.Model(&models.GroupInvite{}).
				Where("invite_id = ?", existing.InviteID).
				Updates(map[string]interface{}{
					"status":      models.InviteStatusPending,
					"from_user":   invite.FromUser,
					"wrapped_key": invite.WrappedKey,
					"key_nonce":   invite.KeyNonce,
					"created_at":  time.Now(),
				})
			if result.Error != nil {
				return fmt.Errorf("refresh invite: %w", result.Error)
			}
			invite.InviteID = existing.InviteID
			return nil
		}
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("lookup existing invite: %w", err)
		}
		if err := tx.Create(invite).Error; err != nil {
			return fmt.Errorf("create invite: %w", err)
		}
		return nil
	})
}

// ListPendingInvites returns the user's pending invitations joined with the
// group name and the inviter's profile, newest first.
func (r *PostgresRepo) ListPendingInvites(ctx context.Context, userID uuid.UUID) ([]GroupInviteInfo, error) {
	// Scan into a flat row shape first — GORM can't scan a join into the nested
	// GroupInviteInfo struct directly.
	type inviteRow struct {
		models.GroupInvite
		GroupName       string
		FromUsername    string
		FromDisplayName string
		FromAvatarURL   *string
	}
	var rows []inviteRow
	err := r.db.WithContext(ctx).
		Table("group_invites").
		Select(`group_invites.*, groups.name AS group_name,
			users.username AS from_username, users.display_name AS from_display_name,
			users.avatar_url AS from_avatar_url`).
		Joins("JOIN groups ON groups.group_id = group_invites.group_id").
		Joins("JOIN users ON users.user_id = group_invites.from_user").
		Where("group_invites.to_user = ? AND group_invites.status = ?", userID, models.InviteStatusPending).
		Order("group_invites.created_at DESC").
		Scan(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("list pending invites: %w", err)
	}

	invites := make([]GroupInviteInfo, 0, len(rows))
	for _, row := range rows {
		displayName := row.FromDisplayName
		if displayName == "" {
			displayName = row.FromUsername
		}
		invites = append(invites, GroupInviteInfo{
			Invite:          row.GroupInvite,
			GroupName:       row.GroupName,
			FromUsername:    row.FromUsername,
			FromDisplayName: displayName,
			FromAvatarURL:   row.FromAvatarURL,
		})
	}
	return invites, nil
}

// AcceptInvite resolves a pending invite addressed to userID: marks it
// accepted and inserts the membership row, copying the wrapped group key from
// the invite so the new member can unwrap it. Returns ErrInviteNotPending if
// the invite doesn't exist, isn't theirs, or was already resolved.
func (r *PostgresRepo) AcceptInvite(ctx context.Context, inviteID, userID uuid.UUID) (*models.GroupInvite, error) {
	var invite models.GroupInvite
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Flip pending→accepted atomically; zero rows means not ours / not pending.
		result := tx.Model(&models.GroupInvite{}).
			Where("invite_id = ? AND to_user = ? AND status = ?", inviteID, userID, models.InviteStatusPending).
			Update("status", models.InviteStatusAccepted)
		if result.Error != nil {
			return fmt.Errorf("accept invite: %w", result.Error)
		}
		if result.RowsAffected == 0 {
			return ErrInviteNotPending
		}
		if err := tx.Where("invite_id = ?", inviteID).First(&invite).Error; err != nil {
			return fmt.Errorf("load accepted invite: %w", err)
		}

		member := models.GroupMember{
			GroupID:    invite.GroupID,
			UserID:     userID,
			Role:       models.GroupRoleMember,
			WrappedKey: invite.WrappedKey,
			KeyNonce:   invite.KeyNonce,
			WrappedBy:  invite.FromUser,
		}
		if err := tx.Create(&member).Error; err != nil {
			// Already a member (e.g. joined via a parallel invite) — treat the
			// accept as done rather than failing the whole transaction.
			if isUniqueViolation(err) {
				return nil
			}
			return fmt.Errorf("create membership from invite: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &invite, nil
}

// DeclineInvite marks a pending invite addressed to userID as declined.
// Returns ErrInviteNotPending if there is nothing pending to decline.
func (r *PostgresRepo) DeclineInvite(ctx context.Context, inviteID, userID uuid.UUID) error {
	result := r.db.WithContext(ctx).Model(&models.GroupInvite{}).
		Where("invite_id = ? AND to_user = ? AND status = ?", inviteID, userID, models.InviteStatusPending).
		Update("status", models.InviteStatusDeclined)
	if result.Error != nil {
		return fmt.Errorf("decline invite: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return ErrInviteNotPending
	}
	return nil
}
