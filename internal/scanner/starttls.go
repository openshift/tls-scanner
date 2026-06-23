package scanner

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// knownStarttlsProtocols lists the STARTTLS protocol names that testssl.sh
// supports via --starttls.
var knownStarttlsProtocols = map[string]bool{
	"ftp":         true,
	"smtp":        true,
	"lmtp":        true,
	"pop3":        true,
	"imap":        true,
	"xmpp":        true,
	"xmpp-server": true,
	"telnet":      true,
	"ldap":        true,
	"nntp":        true,
	"sieve":       true,
	"postgres":    true,
	"mysql":       true,
}

var commToStarttls = map[string]string{
	"postgres":   "postgres",
	"postmaster": "postgres",
	"pgbouncer":  "postgres",
	"mysqld":     "mysql",
	"mariadbd":   "mysql",
}

func StarttlsProtoForProcess(comm string) string {
	return commToStarttls[comm]
}

// ParseStarttlsPorts parses a --starttls-ports flag value into a StarttlsPorts
// map. The format is: protocol=port[:port...][,protocol=port[:port...]]
// Example: postgres=5432:6432,mysql=3306
func ParseStarttlsPorts(value string) (StarttlsPorts, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}

	result := make(StarttlsPorts)
	for _, entry := range strings.Split(value, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		parts := strings.SplitN(entry, "=", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return nil, fmt.Errorf("invalid starttls-ports entry %q: expected protocol=port[:port]", entry)
		}

		proto := strings.TrimSpace(parts[0])
		if !knownStarttlsProtocols[proto] {
			known := make([]string, 0, len(knownStarttlsProtocols))
			for k := range knownStarttlsProtocols {
				known = append(known, k)
			}
			slices.Sort(known)
			return nil, fmt.Errorf("unknown STARTTLS protocol %q (known: %s)", proto, strings.Join(known, ", "))
		}

		for _, portStr := range strings.Split(parts[1], ":") {
			portStr = strings.TrimSpace(portStr)
			port, err := strconv.Atoi(portStr)
			if err != nil || port < 1 || port > 65535 {
				return nil, fmt.Errorf("invalid port %q in starttls-ports entry %q", portStr, entry)
			}
			if existing, ok := result[port]; ok && existing != proto {
				return nil, fmt.Errorf("port %d mapped to both %q and %q", port, existing, proto)
			}
			result[port] = proto
		}
	}

	return result, nil
}
