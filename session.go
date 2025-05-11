package web

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"strconv"
	"sync"
	"time"
)

// Session represents a user session.
type Session struct {
	id         string
	data       Storage // previously: map[string]interface{}
	lastAccess time.Time
}

func (s *Session) ID() string {
	return s.id
}

func (s *Session) LastAccessTime() time.Time {
	return s.lastAccess
}

func (s *Session) Get(key string) (any, bool) {
	return s.data.Get(key)
}

func (s *Session) Set(key string, value any) {
	s.data.Set(key, value)
}

func (s *Session) Del(key string) {
	s.data.Del(key)
}

func (s *Session) Clear() {
	s.data.Clear()
}

// Storage is an interface for session data storage.
type Storage interface {
	Get(key string) (any, bool)
	Set(key string, value any)
	Del(key string)
	ForEach(func(key string, value any))
	List() []string
	Clear()
}

// MemoryStorage is a basic in-memory storage using sync.Map.
type MemoryStorage struct {
	m sync.Map
}

func NewMemoryStorage() *MemoryStorage {
	return &MemoryStorage{}
}

func (ms *MemoryStorage) Get(key string) (any, bool) {
	return ms.m.Load(key)
}

func (ms *MemoryStorage) Set(key string, value any) {
	ms.m.Store(key, value)
}

func (ms *MemoryStorage) Del(key string) {
	ms.m.Delete(key)
}

func (ms *MemoryStorage) Clear() {
	ms.m.Clear()
}

func (ms *MemoryStorage) ForEach(callback func(key string, value any)) {
	ms.m.Range(func(key, value any) bool {
		callback(key.(string), value)
		return true
	})
}

func (ms *MemoryStorage) List() []string {
	var keys []string
	ms.m.Range(func(key, _ any) bool {
		keys = append(keys, key.(string))
		return true
	})
	return keys
}

// SessionManager manages user sessions.
type SessionManager struct {
	storage    Storage
	cookieName string
}

// Define SessionOption type.
type SessionOption func(*SessionManager)

// WithStorage configures a custom Storage implementation for session data.
func WithStorage(storage Storage) SessionOption {
	return func(sm *SessionManager) {
		sm.storage = storage
	}
}

// NewSessionManager creates a new SessionManager with in-memory storage.
func NewSessionManager(cookieName string, opts ...SessionOption) *SessionManager {
	sm := &SessionManager{
		storage:    NewMemoryStorage(),
		cookieName: cookieName,
	}
	for _, opt := range opts {
		opt(sm)
	}
	return sm
}

// LoadSession loads or creates a session attached to the given context.
func (sm *SessionManager) LoadSession(ctx *context) {
	// Attempt to retrieve session ID from cookie.
	sessionID := ctx.GetCookie(sm.cookieName)
	if sessionID != "" {
		if value, ok := sm.storage.Get(sessionID); ok {
			session := value.(*Session)
			session.lastAccess = time.Now()
			ctx.session = session
			return
		}
	}
	// Not found or invalid: create a new session.
	newID := generateSessionID()
	session := &Session{
		id:         newID,
		data:       NewMemoryStorage(), // use Storage instead of map
		lastAccess: time.Now(),
	}
	sm.storage.Set(newID, session)
	ctx.session = session
	// Set session cookie.
	cookie := &Cookie{
		Name:     sm.cookieName,
		Value:    newID,
		Path:     "/",
		HttpOnly: true,
		MaxAge:   3600, // 1-hour expiry (example)
	}
	ctx.SetCookie(cookie)
}

// CreateTemporarySession creates a session that will be automatically deleted after ttl.
func (sm *SessionManager) CreateTemporarySession(ttl time.Duration) *Session {
	newID := generateSessionID()
	session := &Session{
		id:         newID,
		data:       NewMemoryStorage(), // use Storage instead of map
		lastAccess: time.Now(),
	}
	sm.storage.Set(newID, session)
	// Schedule deletion of the session after ttl.
	go func() {
		time.Sleep(ttl)
		sm.storage.Del(newID)
	}()
	return session
}

func generateSessionID() string {
	// generate 16 random bytes and encode
	b := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		// fallback to timestamp-based id
		return strconv.FormatInt(time.Now().UnixNano(), 10)
	}
	return hex.EncodeToString(b)
}
