package scanner

import (
	_ "embed"
	"fmt"
	"log"
	"regexp"

	"gopkg.in/yaml.v3"
)

//go:embed policy.yaml
var embeddedPolicyYAML []byte

// ProfileSource names the TLS profile source that should be used when checking
// compliance for a matched component.
type ProfileSource string

const (
	ProfileAPIServer ProfileSource = "apiserver"
	ProfileIngress   ProfileSource = "ingress"
	ProfileKubelet   ProfileSource = "kubelet"
)

// PolicyRule matches a scanned port by any combination of namespace, process
// name, port number, and component name. Omitted fields act as wildcards.
// String fields are treated as Go regular expressions anchored at both ends
// (i.e. the pattern must match the whole value). When all specified fields
// match, the first such rule wins and the port is checked against Profile.
type PolicyRule struct {
	Namespace string        `yaml:"namespace,omitempty"`
	Process   string        `yaml:"process,omitempty"`
	Port      *int          `yaml:"port,omitempty"`
	Component string        `yaml:"component,omitempty"`
	Profile   ProfileSource `yaml:"profile"`

	// compiled regexes, populated by compile() after unmarshal
	namespaceRe *regexp.Regexp
	processRe   *regexp.Regexp
	componentRe *regexp.Regexp
}

// ComponentPolicy is a prioritised list of PolicyRules. Rules are evaluated
// top-to-bottom; the first matching rule wins. Ports with no matching rule are
// checked against the cluster-wide APIServer TLS profile.
//
// The active policy is defined in policy.yaml and embedded at build time.
// Changes to that file must go through the normal review process.
type ComponentPolicy struct {
	Rules []PolicyRule `yaml:"rules"`
}

// Policy returns the org-wide component policy embedded in the binary.
// It is the single source of truth for which TLS profile applies to each
// component type. To change the policy, edit policy.yaml and submit for review.
func Policy() (*ComponentPolicy, error) {
	var p ComponentPolicy
	if err := yaml.Unmarshal(embeddedPolicyYAML, &p); err != nil {
		return nil, fmt.Errorf("failed to parse embedded policy: %w", err)
	}
	for i := range p.Rules {
		if err := p.Rules[i].compile(); err != nil {
			return nil, fmt.Errorf("policy rule %d: %w", i, err)
		}
	}
	p.warnShadowedRules()
	return &p, nil
}

// warnShadowedRules logs a warning for each rule that can never be reached
// because an earlier, broader rule will always match first.
func (p *ComponentPolicy) warnShadowedRules() {
	for i := 0; i < len(p.Rules); i++ {
		for j := i + 1; j < len(p.Rules); j++ {
			if p.Rules[i].shadows(&p.Rules[j]) {
				log.Printf("Warning: policy rule %d (%s) shadows rule %d (%s) — rule %d will never be reached. "+
					"Check policy.yaml and move more-specific rules before broader ones.",
					i, p.Rules[i].description(),
					j, p.Rules[j].description(),
					j)
			}
		}
	}
}

// shadows reports whether r will always match before other, making other
// unreachable. r shadows other when r's constraints are a superset of
// other's — i.e. r is less specific (or equally specific) in every dimension.
func (r *PolicyRule) shadows(other *PolicyRule) bool {
	// For each dimension: if other has no constraint, r must also have none
	// (otherwise r is more specific and won't match everything other matches).
	// If other has a constraint, r must either have no constraint (wildcard)
	// or a pattern that covers other's literal value.
	if other.namespaceRe == nil {
		if r.namespaceRe != nil {
			return false
		}
	} else if r.namespaceRe != nil && !r.namespaceRe.MatchString(other.Namespace) {
		return false
	}

	if other.processRe == nil {
		if r.processRe != nil {
			return false
		}
	} else if r.processRe != nil && !r.processRe.MatchString(other.Process) {
		return false
	}

	if other.componentRe == nil {
		if r.componentRe != nil {
			return false
		}
	} else if r.componentRe != nil && !r.componentRe.MatchString(other.Component) {
		return false
	}

	if other.Port == nil {
		if r.Port != nil {
			return false
		}
	} else if r.Port != nil && *r.Port != *other.Port {
		return false
	}

	return true
}

// description returns a short human-readable summary of the rule's matchers.
func (r *PolicyRule) description() string {
	s := string(r.Profile) + " {"
	if r.Namespace != "" {
		s += "namespace:" + r.Namespace + " "
	}
	if r.Process != "" {
		s += "process:" + r.Process + " "
	}
	if r.Component != "" {
		s += "component:" + r.Component + " "
	}
	if r.Port != nil {
		s += fmt.Sprintf("port:%d ", *r.Port)
	}
	return s + "}"
}

// compile validates and pre-compiles the rule. It checks that:
//   - profile is a known value
//   - at least one matcher field is set (a rule with no matchers would
//     silently swallow all subsequent rules)
//   - all string matcher fields are valid Go regexes
//
// Patterns are implicitly anchored so "openshift-ingress" matches that exact
// string, while "openshift-.*" matches any string with that prefix.
func (r *PolicyRule) compile() error {
	switch r.Profile {
	case ProfileAPIServer, ProfileIngress, ProfileKubelet:
	case "":
		return fmt.Errorf("profile must be set (valid values: apiserver, ingress, kubelet)")
	default:
		return fmt.Errorf("unknown profile %q (valid values: apiserver, ingress, kubelet)", r.Profile)
	}

	if r.Namespace == "" && r.Process == "" && r.Component == "" && r.Port == nil {
		return fmt.Errorf("at least one matcher field (namespace, process, port, component) must be set")
	}

	var err error
	if r.Namespace != "" {
		if r.namespaceRe, err = regexp.Compile("^(?:" + r.Namespace + ")$"); err != nil {
			return fmt.Errorf("invalid namespace pattern %q: %w", r.Namespace, err)
		}
	}
	if r.Process != "" {
		if r.processRe, err = regexp.Compile("^(?:" + r.Process + ")$"); err != nil {
			return fmt.Errorf("invalid process pattern %q: %w", r.Process, err)
		}
	}
	if r.Component != "" {
		if r.componentRe, err = regexp.Compile("^(?:" + r.Component + ")$"); err != nil {
			return fmt.Errorf("invalid component pattern %q: %w", r.Component, err)
		}
	}
	return nil
}

// Resolve returns the ComponentType for a port with the given attributes by
// evaluating the policy rules in order. Returns GenericComponent if no rule
// matches.
func (p *ComponentPolicy) Resolve(namespace, process, component string, port int) ComponentType {
	for _, rule := range p.Rules {
		if rule.matches(namespace, process, component, port) {
			switch rule.Profile {
			case ProfileIngress:
				return IngressComponent
			case ProfileKubelet:
				return KubeletComponent
			default:
				return GenericComponent
			}
		}
	}
	return GenericComponent
}

func (r *PolicyRule) matches(namespace, process, component string, port int) bool {
	if r.namespaceRe != nil && !r.namespaceRe.MatchString(namespace) {
		return false
	}
	if r.processRe != nil && !r.processRe.MatchString(process) {
		return false
	}
	if r.componentRe != nil && !r.componentRe.MatchString(component) {
		return false
	}
	if r.Port != nil && *r.Port != port {
		return false
	}
	return true
}
