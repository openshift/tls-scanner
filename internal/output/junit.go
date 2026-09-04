package output

import (
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/openshift/tls-scanner/internal/k8s"
	"github.com/openshift/tls-scanner/internal/scanner"
)

func hostname() string {
	h, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return h
}

// tlsAdherenceGate tags adherence testcases so the feature-gate promotion
// tooling (openshift/api) can match them to the TLSAdherence gate. It must
// appear verbatim in every test name that provides promotion evidence.
const tlsAdherenceGate = "[OCPFeatureGate:TLSAdherence]"

type JUnitTestSuite struct {
	XMLName    xml.Name        `xml:"testsuite"`
	Name       string          `xml:"name,attr"`
	Tests      int             `xml:"tests,attr"`
	Failures   int             `xml:"failures,attr"`
	Skipped    int             `xml:"skipped,attr,omitempty"`
	Time       float64         `xml:"time,attr"`
	Timestamp  string          `xml:"timestamp,attr,omitempty"`
	Hostname   string          `xml:"hostname,attr,omitempty"`
	Properties []JUnitProperty `xml:"properties>property,omitempty"`
	TestCases  []JUnitTestCase `xml:"testcase"`
}

type JUnitTestCase struct {
	XMLName   xml.Name      `xml:"testcase"`
	Name      string        `xml:"name,attr"`
	ClassName string        `xml:"classname,attr"`
	Time      float64       `xml:"time,attr"`
	Failure   *JUnitFailure `xml:"failure,omitempty"`
	Skipped   *JUnitSkipped `xml:"skipped,omitempty"`
	SystemOut string        `xml:"system-out,omitempty"`
	SystemErr string        `xml:"system-err,omitempty"`
}

type JUnitFailure struct {
	XMLName xml.Name `xml:"failure"`
	Message string   `xml:"message,attr"`
	Type    string   `xml:"type,attr"`
	Content string   `xml:",chardata"`
}

type JUnitSkipped struct {
	XMLName xml.Name `xml:"skipped"`
	Message string   `xml:"message,attr"`
}

type JUnitProperty struct {
	Name  string `xml:"name,attr"`
	Value string `xml:"value,attr"`
}

// endpointGroup aggregates every scanned pod endpoint that belongs to the
// same workload and port. JUnit testcases are emitted per group, not per
// pod, so the set of test names does not change with replica counts,
// scheduling, or pod-name randomness between runs.
type endpointGroup struct {
	subject   string // stable test-name fragment, e.g. "ns/openshift-dns daemonset/dns-default port/5353"
	className string
	failures  []string
	skips     []string
	scanned   []string
}

// groupSubject returns the stable identity fragment used in test names. IPs
// and pod names must not appear here; they change on every run.
func groupSubject(ipResult scanner.IPResult, port int) (subject, className string) {
	if ipResult.Pod != nil {
		workload := k8s.WorkloadIdentityForPod(ipResult.Pod.Pod)
		if workload.Name == "unknown" && ipResult.Pod.Name != "" {
			workload.Name = ipResult.Pod.Name
		}
		subject = fmt.Sprintf("ns/%s %s port/%d", ipResult.Pod.Namespace, workload, port)
		className = fmt.Sprintf("%s/%s", ipResult.Pod.Namespace, workload)
		return subject, className
	}
	// No pod metadata: fall back to the IP. Such entries cannot be stable
	// across runs, but they should not occur in pod-driven scans.
	return fmt.Sprintf("host/%s port/%d", ipResult.IP, port), ipResult.IP
}

func endpointDescription(ipResult scanner.IPResult, portResult scanner.PortResult) string {
	podName := ipResult.IP
	if ipResult.Pod != nil {
		podName = ipResult.Pod.Name
	}
	return fmt.Sprintf("pod %s (%s:%d)", podName, ipResult.IP, portResult.Port)
}

func WriteJUnitOutput(scanResults scanner.ScanResults, filename string, pqcCheck bool) error {
	testSuite := JUnitTestSuite{
		Name:      "TLSSecurityScan",
		Time:      scanResults.Duration.Seconds(),
		Timestamp: scanResults.Timestamp,
		Hostname:  hostname(),
	}

	enforceTLSCompliance := scanner.TLSConfigComplianceFailuresEnforced(scanResults)

	groups := map[string]*endpointGroup{}
	var groupOrder []string

	for _, ipResult := range scanResults.IPResults {
		for _, portResult := range ipResult.PortResults {
			// Ports with no external TLS surface produce no testcase:
			// pods without listeners, localhost-only listeners, and
			// plaintext health-probe ports are not scannable endpoints.
			if portResult.Status == scanner.StatusNoPorts ||
				portResult.Status == scanner.StatusLocalhostOnly ||
				portResult.Status == scanner.StatusProbePort {
				continue
			}

			subject, className := groupSubject(ipResult, portResult.Port)
			group, ok := groups[subject]
			if !ok {
				group = &endpointGroup{subject: subject, className: className}
				groups[subject] = group
				groupOrder = append(groupOrder, subject)
			}

			endpoint := endpointDescription(ipResult, portResult)

			var failures []string
			if pqcCheck {
				if portResult.Status == scanner.StatusOK {
					if !portResult.TLS13Supported {
						failures = append(failures, "PQC: TLS 1.3 not supported.")
					}
					if !portResult.MLKEMSupported {
						failures = append(failures, "PQC: ML-KEM not supported (no x25519mlkem768 or mlkem768).")
					}
				}
			} else if enforceTLSCompliance {
				if portResult.IngressTLSConfigCompliance != nil && !scanner.IsTLSConfigCompliant(portResult.IngressTLSConfigCompliance) {
					failures = append(failures, "Ingress TLS config is not compliant.")
				}
				if portResult.APIServerTLSConfigCompliance != nil && !scanner.IsTLSConfigCompliant(portResult.APIServerTLSConfigCompliance) {
					failures = append(failures, "API Server TLS config is not compliant.")
				}
				if portResult.KubeletTLSConfigCompliance != nil && !scanner.IsTLSConfigCompliant(portResult.KubeletTLSConfigCompliance) {
					failures = append(failures, "Kubelet TLS config is not compliant.")
				}
			}

			switch {
			case len(failures) > 0:
				group.failures = append(group.failures, fmt.Sprintf("%s: %s", endpoint, strings.Join(failures, " ")))
			case portResult.Status == scanner.StatusOK:
				group.scanned = append(group.scanned, endpoint)
			default:
				reason := portResult.Reason
				if reason == "" {
					reason = string(portResult.Status)
				}
				group.skips = append(group.skips, fmt.Sprintf("%s: %s", endpoint, reason))
			}
		}
	}

	namePrefix := "[sig-security] "
	checkDescription := "TLS profile scan"
	if pqcCheck {
		checkDescription = "should be PQC ready with TLS 1.3 and ML-KEM"
	} else if enforceTLSCompliance {
		namePrefix = "[sig-security]" + tlsAdherenceGate + " "
		checkDescription = "should comply with the cluster TLS profile"
	}

	sort.Strings(groupOrder)
	for _, subject := range groupOrder {
		group := groups[subject]

		testCase := JUnitTestCase{
			Name:      fmt.Sprintf("%s%s %s", namePrefix, group.subject, checkDescription),
			ClassName: group.className,
		}

		switch {
		case len(group.failures) > 0:
			testCase.Failure = &JUnitFailure{
				Message: "TLS Compliance Failed",
				Type:    "TLSComplianceCheck",
				Content: strings.Join(group.failures, "\n"),
			}
			testSuite.Failures++
		case len(group.scanned) == 0:
			// Every endpoint of this workload/port was unreachable for a
			// TLS handshake (e.g. blocked by NetworkPolicy) or served no
			// TLS. Skipping instead of passing keeps unverified endpoints
			// from counting as evidence that the check succeeded.
			testCase.Skipped = &JUnitSkipped{
				Message: strings.Join(group.skips, "; "),
			}
			testSuite.Skipped++
		default:
			testCase.SystemOut = strings.Join(append(group.scanned, group.skips...), "\n")
		}

		testSuite.TestCases = append(testSuite.TestCases, testCase)
	}

	testSuite.Tests = len(testSuite.TestCases)

	dir := filepath.Dir(filename)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("could not create directory for JUnit report: %w", err)
	}

	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("could not create JUnit report file: %w", err)
	}
	defer file.Close()

	if _, err := file.WriteString(xml.Header); err != nil {
		return fmt.Errorf("failed to write XML header to JUnit report: %w", err)
	}

	encoder := xml.NewEncoder(file)
	encoder.Indent("", "  ")
	if err := encoder.Encode(testSuite); err != nil {
		return fmt.Errorf("could not encode JUnit report: %w", err)
	}

	return nil
}
