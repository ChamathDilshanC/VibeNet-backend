// Group chat and invitation endpoints.
//
// Group messages are end-to-end encrypted under a symmetric group key that the
// creator's client generates and wraps per member with the pairwise ECDH key it
// already shares with each of them (the same primitive 1:1 chats use). These
// endpoints therefore only ever move *wrapped* key material — the server can
// route and store it but never recover the group key itself.

package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/ChamathDilshanC/VibeNet-backend/internal/db"
	"github.com/ChamathDilshanC/VibeNet-backend/internal/models"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// wrappedKeyPayload is one member's encrypted copy of the group key, produced
// client-side by whoever is adding them (the creator or an inviter).
type wrappedKeyPayload struct {
	WrappedKey string `json:"wrapped_key"`
	KeyNonce   string `json:"key_nonce"`
}

// createGroupRequest is the body of POST /api/groups/create. SelfKey is the
// creator's own wrapped copy (wrapped to themselves, so any of their devices
// can recover the group key later); Members are contacts added directly at
// creation, each with the key wrapped for them.
type createGroupRequest struct {
	Name    string            `json:"name"`
	SelfKey wrappedKeyPayload `json:"self_key"`
	Members []struct {
		UserID string `json:"user_id"`
		wrappedKeyPayload
	} `json:"members"`
}

// addMemberRequest is the body of POST /api/groups/{id}/members: add a user
// (by username) to the group named in the URL, with the group key wrapped for
// them by the caller's client. Restricted to the group's owner or an admin —
// see requireGroupAdmin.
//
// This records a pending invite rather than an instant membership row: the
// invitee must explicitly accept (see AcceptInvite) before joining, the same
// consent posture the rest of VibeNet uses (e.g. the DM chat-PIN gate). The
// "Add member" name matches how the client presents it — from the acting
// owner/admin's point of view they ARE adding someone — even though it lands
// as a pending invite until accepted.
type addMemberRequest struct {
	Username string `json:"username"`
	wrappedKeyPayload
}

// updateMemberRoleRequest is the body of PUT /api/groups/{id}/members/{user_id}/role.
type updateMemberRoleRequest struct {
	Role string `json:"role"`
}

// inviteActionRequest is the body of POST /api/invites/accept and /decline.
type inviteActionRequest struct {
	InviteID string `json:"invite_id"`
}

// groupMemberDTO is one roster entry in a group response.
type groupMemberDTO struct {
	UserID      string  `json:"user_id"`
	Username    string  `json:"username"`
	DisplayName string  `json:"display_name"`
	AvatarURL   *string `json:"avatar_url,omitempty"`
	Role        string  `json:"role"`
}

// groupDTO is a group as returned to one of its members. The wrapped key
// fields are the *requesting member's own* encrypted copy of the group key
// (plus who wrapped it, so the client knows whose public key to pair with) —
// never another member's.
type groupDTO struct {
	GroupID    string           `json:"group_id"`
	Name       string           `json:"name"`
	CreatedBy  string           `json:"created_by"`
	CreatedAt  int64            `json:"created_at"`
	AvatarURL  *string          `json:"avatar_url,omitempty"`
	Members    []groupMemberDTO `json:"members"`
	WrappedKey string           `json:"wrapped_key"`
	KeyNonce   string           `json:"key_nonce"`
	WrappedBy  string           `json:"wrapped_by"`
}

// inviteDTO is a pending invitation as shown in the invites view.
type inviteDTO struct {
	InviteID        string  `json:"invite_id"`
	GroupID         string  `json:"group_id"`
	GroupName       string  `json:"group_name"`
	FromUserID      string  `json:"from_user_id"`
	FromUsername    string  `json:"from_username"`
	FromDisplayName string  `json:"from_display_name"`
	FromAvatarURL   *string `json:"from_avatar_url,omitempty"`
	CreatedAt       int64   `json:"created_at"`
}

// Frames pushed over the WebSocket from these endpoints so the affected users'
// UIs update live. Both are lightweight change notifications: the client
// refetches the relevant list rather than trusting a partial payload.
type groupUpdateFrame struct {
	Type    string `json:"type"`
	GroupID string `json:"group_id"`
	// Name lets the client toast "You were added to <name>" without a round trip.
	Name string `json:"name,omitempty"`
}

// removedFromGroupFrame is delivered directly to a member an owner/admin just
// removed. It has to be its own frame rather than riding on notifyGroupUpdated:
// by the time that fans out to the remaining roster, the removed user isn't in
// it anymore and would never otherwise learn they're gone.
type removedFromGroupFrame struct {
	Type      string `json:"type"`
	GroupID   string `json:"group_id"`
	GroupName string `json:"group_name"`
}

type inviteReceivedFrame struct {
	Type      string `json:"type"`
	InviteID  string `json:"invite_id"`
	GroupID   string `json:"group_id"`
	GroupName string `json:"group_name"`
	// FromName is the inviter's display name, for the notification toast.
	FromName string `json:"from_name"`
}

func toGroupDTO(g *db.GroupWithMembers) groupDTO {
	members := make([]groupMemberDTO, 0, len(g.Members))
	for _, m := range g.Members {
		members = append(members, groupMemberDTO{
			UserID:      m.UserID.String(),
			Username:    m.Username,
			DisplayName: m.DisplayName,
			AvatarURL:   m.AvatarURL,
			Role:        m.Role,
		})
	}
	return groupDTO{
		GroupID:    g.Group.GroupID.String(),
		Name:       g.Group.Name,
		CreatedBy:  g.Group.CreatedBy.String(),
		CreatedAt:  g.Group.CreatedAt.UnixMilli(),
		AvatarURL:  g.Group.AvatarURL,
		Members:    members,
		WrappedKey: g.Membership.WrappedKey,
		KeyNonce:   g.Membership.KeyNonce,
		WrappedBy:  g.Membership.WrappedBy.String(),
	}
}

// requireGroupMember parses the {id} route param and verifies the caller
// belongs to that group, writing the error response itself when not. Shared
// guard for the group-settings endpoints (rename, photo) that any member may use.
func (h *Handler) requireGroupMember(w http.ResponseWriter, r *http.Request, userID uuid.UUID) (uuid.UUID, bool) {
	groupID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid group id")
		return uuid.Nil, false
	}
	isMember, err := h.postgres.IsGroupMember(r.Context(), groupID, userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to verify group membership")
		return uuid.Nil, false
	}
	if !isMember {
		writeError(w, http.StatusForbidden, "you are not a member of this group")
		return uuid.Nil, false
	}
	return groupID, true
}

// requireGroupAdmin parses the {id} route param and verifies the caller is a
// member of that group with role "owner" or "admin" — the authorization gate
// for member-management actions (adding members, promoting/demoting). Writes
// the error response itself when the check fails: 403 for a regular member or
// a non-member, matching the "reject requests from regular members" policy.
func (h *Handler) requireGroupAdmin(w http.ResponseWriter, r *http.Request, userID uuid.UUID) (uuid.UUID, bool) {
	groupID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid group id")
		return uuid.Nil, false
	}
	role, err := h.postgres.GetGroupMemberRole(r.Context(), groupID, userID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			writeError(w, http.StatusForbidden, "you are not a member of this group")
			return uuid.Nil, false
		}
		writeError(w, http.StatusInternalServerError, "failed to verify group membership")
		return uuid.Nil, false
	}
	if role != models.GroupRoleOwner && role != models.GroupRoleAdmin {
		writeError(w, http.StatusForbidden, "only the group owner or an admin can do this")
		return uuid.Nil, false
	}
	return groupID, true
}

// notifyGroupUpdated nudges every member's live clients that the group's
// settings or roster changed, so sidebars and open headers refresh. The frame
// deliberately omits the name — a name is only attached when someone is being
// ADDED to a group (it drives the "You were added" toast).
func (h *Handler) notifyGroupUpdated(ctx context.Context, groupID uuid.UUID) {
	memberIDs, err := h.postgres.GetGroupMemberIDs(ctx, groupID)
	if err != nil {
		return
	}
	for _, memberID := range memberIDs {
		h.deliverFrame(memberID, groupUpdateFrame{
			Type:    "group_update",
			GroupID: groupID.String(),
		})
	}
}

// UpdateGroup renames a group. Any member may rename (matching the invite
// policy); the change is broadcast so every member's UI updates live.
func (h *Handler) UpdateGroup(w http.ResponseWriter, r *http.Request) {
	userID, ok := UserIDFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	groupID, ok := h.requireGroupMember(w, r, userID)
	if !ok {
		return
	}

	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if err := validateGroupName(req.Name); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := h.postgres.UpdateGroupName(r.Context(), groupID, req.Name); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to rename group")
		return
	}

	full, err := h.postgres.GetGroupWithMembers(r.Context(), groupID, userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to load group")
		return
	}

	h.notifyGroupUpdated(r.Context(), groupID)
	writeJSON(w, http.StatusOK, toGroupDTO(full))
}

// UploadGroupAvatar sets the group photo from a multipart "avatar" upload,
// stored exactly like user avatars. Any member may change it; the update is
// broadcast so every member's sidebar and header refresh live.
func (h *Handler) UploadGroupAvatar(w http.ResponseWriter, r *http.Request) {
	userID, ok := UserIDFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	groupID, ok := h.requireGroupMember(w, r, userID)
	if !ok {
		return
	}

	avatarURL, objectKey, ok := h.storeUploadedAvatar(w, r, "groups/")
	if !ok {
		return
	}

	if err := h.postgres.UpdateGroupAvatar(r.Context(), groupID, avatarURL); err != nil {
		// Don't leave an orphaned object behind if the DB write fails.
		h.avatarStore.Delete(r.Context(), objectKey)
		if errors.Is(err, gorm.ErrRecordNotFound) {
			writeError(w, http.StatusNotFound, "group not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to update group photo")
		return
	}

	full, err := h.postgres.GetGroupWithMembers(r.Context(), groupID, userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to load group")
		return
	}

	h.notifyGroupUpdated(r.Context(), groupID)
	writeJSON(w, http.StatusOK, toGroupDTO(full))
}

// deliverFrame marshals and pushes a frame to one user's live connection.
// Best-effort: a nil broadcaster (tests) or an offline user simply skips it —
// clients also refetch groups/invites on reconnect and mount.
func (h *Handler) deliverFrame(userID uuid.UUID, frame any) {
	if h.broadcaster == nil {
		return
	}
	payload, err := json.Marshal(frame)
	if err != nil {
		return
	}
	h.broadcaster.DeliverToUser(userID, payload)
}

// validateGroupName bounds the group's display name to the column width.
func validateGroupName(name string) error {
	switch {
	case name == "":
		return errors.New("group name is required")
	case len(name) > 64:
		return errors.New("group name must be at most 64 characters")
	}
	return nil
}

// CreateGroup initialises a new group: the caller becomes its owner and any
// listed contacts become members immediately, each row carrying the group key
// wrapped for that member by the caller's client. Members' UIs are nudged live
// with a group_update frame.
func (h *Handler) CreateGroup(w http.ResponseWriter, r *http.Request) {
	userID, ok := UserIDFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var req createGroupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	req.Name = strings.TrimSpace(req.Name)
	if err := validateGroupName(req.Name); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.SelfKey.WrappedKey == "" || req.SelfKey.KeyNonce == "" {
		writeError(w, http.StatusBadRequest, "self_key with wrapped_key and key_nonce is required")
		return
	}

	// Creator first, then direct-added members. Every wrap here was performed
	// by the creator, so wrapped_by is the creator for all initial rows.
	members := []models.GroupMember{{
		UserID:     userID,
		Role:       models.GroupRoleOwner,
		WrappedKey: req.SelfKey.WrappedKey,
		KeyNonce:   req.SelfKey.KeyNonce,
		WrappedBy:  userID,
	}}
	seen := map[uuid.UUID]bool{userID: true}
	for _, m := range req.Members {
		memberID, err := uuid.Parse(m.UserID)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid member user_id")
			return
		}
		if seen[memberID] {
			continue
		}
		if m.WrappedKey == "" || m.KeyNonce == "" {
			writeError(w, http.StatusBadRequest, "each member needs wrapped_key and key_nonce")
			return
		}
		seen[memberID] = true
		members = append(members, models.GroupMember{
			UserID:     memberID,
			Role:       models.GroupRoleMember,
			WrappedKey: m.WrappedKey,
			KeyNonce:   m.KeyNonce,
			WrappedBy:  userID,
		})
	}

	group, err := h.postgres.CreateGroupWithMembers(r.Context(), req.Name, userID, members)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create group")
		return
	}

	full, err := h.postgres.GetGroupWithMembers(r.Context(), group.GroupID, userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to load created group")
		return
	}

	// Tell the directly-added members their sidebar just gained a group.
	for _, m := range members[1:] {
		h.deliverFrame(m.UserID, groupUpdateFrame{
			Type:    "group_update",
			GroupID: group.GroupID.String(),
			Name:    group.Name,
		})
	}

	writeJSON(w, http.StatusCreated, toGroupDTO(full))
}

// ListGroups returns every group the caller belongs to, with rosters and the
// caller's wrapped copy of each group key.
func (h *Handler) ListGroups(w http.ResponseWriter, r *http.Request) {
	userID, ok := UserIDFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	groups, err := h.postgres.ListGroupsForUser(r.Context(), userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list groups")
		return
	}

	dtos := make([]groupDTO, 0, len(groups))
	for i := range groups {
		dtos = append(dtos, toGroupDTO(&groups[i]))
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"groups": dtos})
}

// AddGroupMember sends (or refreshes) an invitation for a user, looked up by
// username, to join the group identified in the URL. Restricted to the
// group's owner or an admin — a regular member is rejected with 403 (see
// requireGroupAdmin). The invitee is nudged live with an invite_received
// frame so their invites badge updates immediately; they still need to accept
// (see AcceptInvite) before they actually join.
func (h *Handler) AddGroupMember(w http.ResponseWriter, r *http.Request) {
	userID, ok := UserIDFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	groupID, ok := h.requireGroupAdmin(w, r, userID)
	if !ok {
		return
	}

	var req addMemberRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" {
		writeError(w, http.StatusBadRequest, "username is required")
		return
	}
	if req.WrappedKey == "" || req.KeyNonce == "" {
		writeError(w, http.StatusBadRequest, "wrapped_key and key_nonce are required")
		return
	}

	target, err := h.postgres.GetUserByUsername(r.Context(), req.Username)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			writeError(w, http.StatusNotFound, "user not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to look up user")
		return
	}
	if target.UserID == userID {
		writeError(w, http.StatusBadRequest, "you cannot invite yourself")
		return
	}

	alreadyMember, err := h.postgres.IsGroupMember(r.Context(), groupID, target.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to verify group membership")
		return
	}
	if alreadyMember {
		writeError(w, http.StatusConflict, "user is already a member of this group")
		return
	}

	invite := &models.GroupInvite{
		GroupID:    groupID,
		FromUser:   userID,
		ToUser:     target.UserID,
		Status:     models.InviteStatusPending,
		WrappedKey: req.WrappedKey,
		KeyNonce:   req.KeyNonce,
	}
	if err := h.postgres.CreateInvite(r.Context(), invite); err != nil {
		if errors.Is(err, db.ErrAlreadyGroupMember) {
			writeError(w, http.StatusConflict, "user is already a member of this group")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to create invite")
		return
	}

	// Live nudge for the invitee. Group name + inviter name make the toast
	// self-explanatory; look them up best-effort.
	groupName := ""
	if full, err := h.postgres.GetGroupWithMembers(r.Context(), groupID, userID); err == nil {
		groupName = full.Group.Name
	}
	fromName := ""
	if me, err := h.postgres.GetUserByID(r.Context(), userID); err == nil {
		fromName = displayNameOfUser(me)
	}
	h.deliverFrame(target.UserID, inviteReceivedFrame{
		Type:      "invite_received",
		InviteID:  invite.InviteID.String(),
		GroupID:   groupID.String(),
		GroupName: groupName,
		FromName:  fromName,
	})

	writeJSON(w, http.StatusCreated, map[string]string{
		"invite_id": invite.InviteID.String(),
		"status":    invite.Status,
	})
}

// ListInvites returns the caller's pending group invitations.
func (h *Handler) ListInvites(w http.ResponseWriter, r *http.Request) {
	userID, ok := UserIDFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	invites, err := h.postgres.ListPendingInvites(r.Context(), userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list invites")
		return
	}

	dtos := make([]inviteDTO, 0, len(invites))
	for _, inv := range invites {
		dtos = append(dtos, inviteDTO{
			InviteID:        inv.Invite.InviteID.String(),
			GroupID:         inv.Invite.GroupID.String(),
			GroupName:       inv.GroupName,
			FromUserID:      inv.Invite.FromUser.String(),
			FromUsername:    inv.FromUsername,
			FromDisplayName: inv.FromDisplayName,
			FromAvatarURL:   inv.FromAvatarURL,
			CreatedAt:       inv.Invite.CreatedAt.UnixMilli(),
		})
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"invites": dtos})
}

// AcceptInvite joins the caller to the invite's group and returns the full
// group (roster + their wrapped key) so the client can open it immediately.
// Existing members get a group_update nudge so their roster refreshes live.
func (h *Handler) AcceptInvite(w http.ResponseWriter, r *http.Request) {
	userID, ok := UserIDFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var req inviteActionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	inviteID, err := uuid.Parse(strings.TrimSpace(req.InviteID))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid invite_id")
		return
	}

	invite, err := h.postgres.AcceptInvite(r.Context(), inviteID, userID)
	if err != nil {
		if errors.Is(err, db.ErrInviteNotPending) {
			writeError(w, http.StatusNotFound, "no pending invite found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to accept invite")
		return
	}

	// The hub's cached fan-out list for this group is now stale — drop it so
	// the new member starts receiving group messages right away.
	if h.broadcaster != nil {
		h.broadcaster.InvalidateGroup(invite.GroupID)
	}

	full, err := h.postgres.GetGroupWithMembers(r.Context(), invite.GroupID, userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to load group")
		return
	}

	// Nudge the existing members so their member lists refresh live.
	for _, m := range full.Members {
		if m.UserID == userID {
			continue
		}
		h.deliverFrame(m.UserID, groupUpdateFrame{
			Type:    "group_update",
			GroupID: invite.GroupID.String(),
		})
	}

	writeJSON(w, http.StatusOK, toGroupDTO(full))
}

// DeclineInvite marks a pending invite as declined.
func (h *Handler) DeclineInvite(w http.ResponseWriter, r *http.Request) {
	userID, ok := UserIDFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var req inviteActionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	inviteID, err := uuid.Parse(strings.TrimSpace(req.InviteID))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid invite_id")
		return
	}

	if err := h.postgres.DeclineInvite(r.Context(), inviteID, userID); err != nil {
		if errors.Is(err, db.ErrInviteNotPending) {
			writeError(w, http.StatusNotFound, "no pending invite found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to decline invite")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": models.InviteStatusDeclined})
}

// UpdateMemberRole promotes a member to admin or demotes an admin back to
// member. Restricted to the group's owner or an admin (see requireGroupAdmin);
// the owner's own role is immutable through this endpoint — VibeNet has no
// separate ownership-transfer flow (see LeaveGroup for how ownership actually
// moves). The updated roster is broadcast so every member's role badges
// refresh live.
func (h *Handler) UpdateMemberRole(w http.ResponseWriter, r *http.Request) {
	userID, ok := UserIDFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	groupID, ok := h.requireGroupAdmin(w, r, userID)
	if !ok {
		return
	}

	targetID, err := uuid.Parse(chi.URLParam(r, "user_id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid user id")
		return
	}

	var req updateMemberRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.Role = strings.TrimSpace(req.Role)
	if req.Role != models.GroupRoleAdmin && req.Role != models.GroupRoleMember {
		writeError(w, http.StatusBadRequest, `role must be "admin" or "member"`)
		return
	}

	targetRole, err := h.postgres.GetGroupMemberRole(r.Context(), groupID, targetID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			writeError(w, http.StatusNotFound, "that user is not a member of this group")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to verify target membership")
		return
	}
	if targetRole == models.GroupRoleOwner {
		writeError(w, http.StatusForbidden, "the group owner's role cannot be changed")
		return
	}

	if err := h.postgres.UpdateMemberRole(r.Context(), groupID, targetID, req.Role); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to update member role")
		return
	}

	full, err := h.postgres.GetGroupWithMembers(r.Context(), groupID, userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to load group")
		return
	}

	h.notifyGroupUpdated(r.Context(), groupID)
	writeJSON(w, http.StatusOK, toGroupDTO(full))
}

// LeaveGroup removes the caller from the group named in the URL. If they were
// its last member, the group (and any pending invites for it) is deleted
// outright; if they were the owner and others remain, ownership automatically
// passes to the earliest-joined remaining member (see db.LeaveGroup).
// Remaining members are nudged live so their roster — and any new "Owner"
// badge — refreshes without a reload.
func (h *Handler) LeaveGroup(w http.ResponseWriter, r *http.Request) {
	userID, ok := UserIDFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	groupID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid group id")
		return
	}

	deleted, err := h.postgres.LeaveGroup(r.Context(), groupID, userID)
	if err != nil {
		if errors.Is(err, db.ErrNotGroupMember) {
			writeError(w, http.StatusNotFound, "you are not a member of this group")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to leave group")
		return
	}

	// Stale either way: membership shrank, or the group is gone entirely.
	if h.broadcaster != nil {
		h.broadcaster.InvalidateGroup(groupID)
	}
	if !deleted {
		h.notifyGroupUpdated(r.Context(), groupID)
	}

	writeJSON(w, http.StatusOK, map[string]bool{"left": true})
}

// RemoveGroupMember removes another member from the group. The owner and
// admins may remove a regular member; only the owner may remove an admin (an
// admin cannot remove a fellow admin) — the group's owner can never be
// removed here at all, matching the immutable-owner rule UpdateMemberRole
// already enforces. Removing yourself this way is rejected in favour of the
// dedicated leave endpoint.
//
// This reuses db.LeaveGroup — the actual data operation (delete the member
// row, hand off ownership or delete the group if it empties out) is identical
// whether the departure is voluntary or not. Because the caller (an existing
// owner/admin) always remains, the group is never deleted by a removal.
func (h *Handler) RemoveGroupMember(w http.ResponseWriter, r *http.Request) {
	userID, ok := UserIDFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	groupID, ok := h.requireGroupAdmin(w, r, userID)
	if !ok {
		return
	}

	targetID, err := uuid.Parse(chi.URLParam(r, "user_id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid user id")
		return
	}
	if targetID == userID {
		writeError(w, http.StatusBadRequest, "use the leave endpoint to remove yourself")
		return
	}

	targetRole, err := h.postgres.GetGroupMemberRole(r.Context(), groupID, targetID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			writeError(w, http.StatusNotFound, "that user is not a member of this group")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to verify target membership")
		return
	}
	if targetRole == models.GroupRoleOwner {
		writeError(w, http.StatusForbidden, "the group owner cannot be removed")
		return
	}
	if targetRole == models.GroupRoleAdmin {
		callerRole, err := h.postgres.GetGroupMemberRole(r.Context(), groupID, userID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to verify your membership")
			return
		}
		if callerRole != models.GroupRoleOwner {
			writeError(w, http.StatusForbidden, "only the group owner can remove an admin")
			return
		}
	}

	if _, err := h.postgres.LeaveGroup(r.Context(), groupID, targetID); err != nil {
		if errors.Is(err, db.ErrNotGroupMember) {
			writeError(w, http.StatusNotFound, "that user is not a member of this group")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to remove member")
		return
	}

	if h.broadcaster != nil {
		h.broadcaster.InvalidateGroup(groupID)
	}

	full, err := h.postgres.GetGroupWithMembers(r.Context(), groupID, userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to load group")
		return
	}

	h.notifyGroupUpdated(r.Context(), groupID)
	h.deliverFrame(targetID, removedFromGroupFrame{
		Type:      "removed_from_group",
		GroupID:   groupID.String(),
		GroupName: full.Group.Name,
	})

	writeJSON(w, http.StatusOK, toGroupDTO(full))
}
