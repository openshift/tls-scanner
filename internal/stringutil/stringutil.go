package stringutil

import "strings"

// NormalizeHost trims whitespace and strips IPv6 square brackets from a host string.
func NormalizeHost(host string) string {
	host = strings.TrimSpace(host)
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") && len(host) >= 2 {
		return host[1 : len(host)-1]
	}
	return host
}

// RemoveDuplicates returns a new slice with duplicates and empty strings removed,
// preserving the original order.
func RemoveDuplicates(slice []string) []string {
	keys := make(map[string]bool)
	var result []string
	for _, item := range slice {
		if !keys[item] && item != "" {
			keys[item] = true
			result = append(result, item)
		}
	}
	return result
}
