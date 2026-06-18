package output

import (
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/openshift/tls-scanner/internal/scanner"
)

func hostname() string {
	h, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return h
}

type JUnitTestSuite struct {
	XMLName    xml.Name        `xml:"testsuite"`
	Name       string          `xml:"name,attr"`
	Tests      int             `xml:"tests,attr"`
	Failures   int             `xml:"failures,attr"`
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
	SystemOut string        `xml:"system-out,omitempty"`
	SystemErr string        `xml:"system-err,omitempty"`
}

type JUnitFailure struct {
	XMLName xml.Name `xml:"failure"`
	Message string   `xml:"message,attr"`
	Type    string   `xml:"type,attr"`
	Content string   `xml:",chardata"`
}

type JUnitProperty struct {
	Name  string `xml:"name,attr"`
	Value string `xml:"value,attr"`
}

func WriteJUnitOutput(scanResults scanner.ScanResults, filename string, pqcCheck bool) error {
	testSuite := JUnitTestSuite{
		Name:      "TLSSecurityScan",
		Time:      scanResults.Duration.Seconds(),
		Timestamp: scanResults.Timestamp,
		Hostname:  hostname(),
	}

	enforceTLSCompliance := scanner.TLSConfigComplianceFailuresEnforced(scanResults)

	for _, ipResult := range scanResults.IPResults {
		for _, portResult := range ipResult.PortResults {
			className := ipResult.IP
			if ipResult.Pod != nil {
				className = ipResult.Pod.Name
			}

			namePrefix := "[TLS Profile] "
			if pqcCheck {
				namePrefix = "[PQC] "
			}

			testCase := JUnitTestCase{
				Name:      fmt.Sprintf("%s%s:%d - %s", namePrefix, ipResult.IP, portResult.Port, portResult.Service),
				ClassName: className,
			}

			var failures []string
			if pqcCheck {
				if portResult.Status != scanner.StatusNoPorts &&
					portResult.Status != scanner.StatusLocalhostOnly &&
					portResult.Status != scanner.StatusNoTLS &&
					portResult.Status != scanner.StatusProbePort {
					if !portResult.TLS13Supported {
						failures = append(failures, "PQC: TLS 1.3 not supported.")
					}
					if !portResult.MLKEMSupported {
						failures = append(failures, "PQC: ML-KEM not supported (no x25519mlkem768 or mlkem768).")
					}
				}
			} else {
				if enforceTLSCompliance {
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
			}

			if len(failures) > 0 {
				testCase.Failure = &JUnitFailure{
					Message: "TLS Compliance Failed",
					Type:    "TLSComplianceCheck",
					Content: strings.Join(failures, "\n"),
				}
				testSuite.Failures++
			}

			testSuite.TestCases = append(testSuite.TestCases, testCase)
		}
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
