// VibeNet — presigned S3 URLs for end-to-end encrypted file/image attachments.
//
// The Go backend never sees a plaintext byte of an uploaded file, and never
// proxies the upload or download itself: the client encrypts the file with a
// random AES-256-GCM key entirely in the browser (see the frontend's
// lib/fileCrypto.ts), uploads the ciphertext straight to S3 using the
// presigned PUT URL from GetUploadURL, then E2EE-encrypts the AES key/IV
// alongside the S3 object key inside the normal chat-message envelope (the
// same pipeline that already encrypts text — see messageStore.ts) so only the
// intended recipient(s) can ever recover the file key. This file's only job
// is minting short-lived signed URLs; it holds no file content.
package api

import (
	"net/http"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

// attachmentKeyPrefix namespaces every object this endpoint ever signs — both
// where GetUploadURL writes new keys and the prefix GetDownloadURL requires,
// so a caller can never presign a GET for an arbitrary path elsewhere in the
// bucket (avatars live under a separate prefix entirely; see UploadAvatar).
const attachmentKeyPrefix = "chat-attachments/"

// presignExpiry bounds how long an upload or download URL stays valid. Short
// on purpose: the upload URL is used once, seconds after being issued; the
// download URL is re-requested fresh every time a recipient renders an
// attachment (see GetDownloadURL's doc comment), so chat history never
// depends on a long-lived signature to keep working.
const presignExpiry = 10 * time.Minute

// safeExtPattern matches a short, plain alphanumeric file extension. Used only
// to make S3 keys mildly more readable in the console — never trusted for
// anything security-relevant, since the object it names is opaque ciphertext
// regardless of the original file's real type.
var safeExtPattern = regexp.MustCompile(`^\.[A-Za-z0-9]{1,8}$`)

// safeExt extracts a short, sanitized extension from a client-supplied
// filename, or "" if it doesn't look like one. Never used to build a path —
// only appended to a fresh server-generated UUID.
func safeExt(filename string) string {
	ext := path.Ext(filename)
	if safeExtPattern.MatchString(ext) {
		return strings.ToLower(ext)
	}
	return ""
}

type presignedUploadResponse struct {
	UploadURL string `json:"upload_url"`
	FileKey   string `json:"file_key"`
	ExpiresIn int64  `json:"expires_in"`
}

// GetUploadURL mints a presigned S3 PUT URL for a fresh, server-generated
// object key. filename/filetype are read only to pick a cosmetic extension;
// the actual key is always a random UUID under attachmentKeyPrefix; no
// client-supplied path ever reaches S3.
func (h *Handler) GetUploadURL(w http.ResponseWriter, r *http.Request) {
	if h.s3 == nil {
		writeError(w, http.StatusServiceUnavailable, "file uploads are not configured")
		return
	}

	filename := strings.TrimSpace(r.URL.Query().Get("filename"))
	key := attachmentKeyPrefix + uuid.NewString() + safeExt(filename)

	uploadURL, err := h.s3.PresignPutURL(r.Context(), key, presignExpiry)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create upload url")
		return
	}

	writeJSON(w, http.StatusOK, presignedUploadResponse{
		UploadURL: uploadURL,
		FileKey:   key,
		ExpiresIn: int64(presignExpiry.Seconds()),
	})
}

type presignedDownloadResponse struct {
	DownloadURL string `json:"download_url"`
}

// GetDownloadURL mints a fresh presigned S3 GET URL for a previously-uploaded
// attachment key. Called on demand each time a recipient's client renders an
// attachment (see MessageAttachment.tsx) rather than once at send time, so
// the signed URL embedded nowhere in chat history ever goes stale — only the
// key itself (inside the E2EE envelope) needs to remain valid indefinitely.
func (h *Handler) GetDownloadURL(w http.ResponseWriter, r *http.Request) {
	if h.s3 == nil {
		writeError(w, http.StatusServiceUnavailable, "file uploads are not configured")
		return
	}

	key := strings.TrimSpace(r.URL.Query().Get("key"))
	// Must be exactly one of our own generated keys — never a path elsewhere in
	// the bucket, and never one containing "..".
	if !strings.HasPrefix(key, attachmentKeyPrefix) || strings.Contains(key, "..") {
		writeError(w, http.StatusBadRequest, "invalid file key")
		return
	}

	downloadURL, err := h.s3.PresignGetURL(r.Context(), key, presignExpiry)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create download url")
		return
	}

	writeJSON(w, http.StatusOK, presignedDownloadResponse{DownloadURL: downloadURL})
}
