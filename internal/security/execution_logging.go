package security

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
)

func argumentNames(args map[string]interface{}) []string {
	names := make([]string, 0, len(args))
	for key := range args {
		names = append(names, key)
	}
	sort.Strings(names)
	return names
}
func commandFingerprint(command string) string {
	sum := sha256.Sum256([]byte(command))
	return hex.EncodeToString(sum[:])
}
