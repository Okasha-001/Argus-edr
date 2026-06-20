package enrich

import (
	"os/user"
	"strconv"
	"sync"
)

// UserResolver maps uids to names, caching both hits and misses so a busy uid is
// looked up once. The lookup is injectable for testing.
type UserResolver struct {
	mu     sync.Mutex
	cache  map[uint32]string
	lookup func(uint32) (string, bool)
}

// NewUserResolver returns a resolver backed by the system user database.
func NewUserResolver() *UserResolver {
	return &UserResolver{cache: make(map[uint32]string), lookup: lookupSystemUser}
}

// Name returns the username for uid, or "" if it cannot be resolved.
func (r *UserResolver) Name(uid uint32) string {
	r.mu.Lock()
	defer r.mu.Unlock()

	if name, ok := r.cache[uid]; ok {
		return name
	}
	name, _ := r.lookup(uid)
	r.cache[uid] = name
	return name
}

func lookupSystemUser(uid uint32) (string, bool) {
	u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
	if err != nil {
		return "", false
	}
	return u.Username, true
}
