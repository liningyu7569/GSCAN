package sqlite

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

// newID 生成带有指定前缀的唯一ID，格式为 prefix-timestamp-hex
func newID(prefix string) string {
	var raw [6]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
	}
	return fmt.Sprintf("%s-%d-%s", prefix, time.Now().UTC().UnixNano(), hex.EncodeToString(raw[:]))
}
