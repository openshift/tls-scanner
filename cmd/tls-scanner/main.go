package main

import (
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/openshift/tls-scanner/internal/k8s"
	"github.com/openshift/tls-scanner/internal/output"
	"github.com/openshift/tls-scanner/internal/scanner"
	"github.com/openshift/tls-scanner/internal/timing"
)

var (
	version = "dev"
	commit  = "unknown"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) (exitCode int) {
	var finalScanResults *scanner.ScanResults
	var isPQCCheck bool

	defer func() {
		if finalScanResults == nil {
			return
		}
		if isPQCCheck {
			// SkipUnscannable excludes NoPorts/LocalhostOnly/NoTLS — swap with a custom PortFilter if rules change
			if scanner.HasPQCComplianceFailures(*finalScanResults, scanner.SkipUnscannable) {
				fmt.Println("\nPQC COMPLIANCE CHECK: FAILED")
				fmt.Println("One or more endpoints do not support TLS 1.3 + ML-KEM (x25519mlkem768 or mlkem768)")
				exitCode = 1
				return
			}
			fmt.Println("\nPQC COMPLIANCE CHECK: PASSED")
			fmt.Println("All endpoints support TLS 1.3 + ML-KEM")
		} else {
			if scanner.HasComplianceFailures(*finalScanResults) {
				exitCode = 1
			}
		}
	}()

	fs := flag.NewFlagSet("tls-scanner", flag.ContinueOnError)
	host := fs.String("host", "127.0.0.1", "The target host or IP address to scan")
	port := fs.String("port", "443", "The target port to scan")
	artifactDir := fs.String("artifact-dir", "/tmp", "Directory to save the artifacts to")
	jsonFile := fs.String("json-file", "", "Output results in JSON format to specified file in artifact-dir")
	csvFile := fs.String("csv-file", "", "Output results in CSV format to specified file in artifact-dir")
	junitFile := fs.String("junit-file", "", "Output results in JUnit XML format to specified file in artifact-dir")
	concurrentScans := fs.Int("j", 0, "Number of concurrent scans; 0 = runtime.NumCPU()")
	allPods := fs.Bool("all-pods", false, "Scan all pods in the cluster (overrides --host)")
	componentFilter := fs.String("component-filter", "", "Filter pods by a comma-separated list of component names (only used with --all-pods)")
	namespaceFilter := fs.String("namespace-filter", "", "Filter pods by a comma-separated list of namespaces (only used with --all-pods)")
	excludeLabels := fs.String("exclude-labels", "", "Exclude pods matching a comma-separated list of label selectors, e.g. 'olm.catalogSource' or 'app=catalog,tier=frontend' (only used with --all-pods). A pod is excluded when ALL selectors match (AND semantics).")
	targets := fs.String("targets", "", "A comma-separated list of host:port targets to scan")
	templateFile := fs.String("template", "", "Path to a YAML file listing hosts and ports to scan (see --generate-template)")
	generateTemplate := fs.String("generate-template", "", "Write a sample targets YAML template to this path and exit")
	limitIPs := fs.Int("limit-ips", 0, "Limit the number of IPs to scan for testing purposes (0 = no limit)")
	logFile := fs.String("log-file", "", "Redirect all log output to the specified file")
	pqcCheck := fs.Bool("pqc-check", false, "Quick check for TLS 1.3 and ML-KEM (post-quantum) support only")
	timingFile := fs.String("timing-file", "", "Output timing report to specified file in artifact-dir")
	dryRun := fs.Bool("dry-run", false, "Discover scan targets and print them without scanning")
	showVersion := fs.Bool("version", false, "Print version and exit")
	logLevel := fs.String("log-level", "info", "Log level: debug, info, warn, error")
	scanTimeoutPerTarget := fs.Int("scan-timeout-per-target", scanner.DefaultScanTimeouts.PerTargetSeconds, "Seconds per target for batch scan timeout calculation")
	connectTimeout := fs.Int("connect-timeout", scanner.DefaultScanTimeouts.ConnectTimeout, "Timeout in seconds for testssl.sh connect and openssl operations")
	tlsProfileType := fs.String("tls-profile-type", "", "Expected cluster TLS profile type for compliance checks (Old, Intermediate, Modern). When set, skips reading APIServer/cluster from the API.")
	starttlsPortsFlag := fs.String("starttls-ports", "", "STARTTLS protocol-to-port mapping (e.g., postgres=5432:6432,mysql=3306)")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	var level slog.Level
	if err := level.UnmarshalText([]byte(*logLevel)); err != nil {
		fmt.Fprintf(os.Stderr, "Error: invalid log level %q (valid: debug, info, warn, error)\n", *logLevel)
		return 2
	}
	logOutput := os.Stderr
	if *logFile != "" {
		f, err := os.OpenFile(*logFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644) //nolint:gosec // G302: log file in emptyDir volume, needs to be readable by kubectl cp
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: opening log file: %v\n", err)
			return 1
		}
		defer func() {
			if cerr := f.Close(); cerr != nil {
				slog.Warn("failed to close log file", "error", cerr)
			}
		}()
		logOutput = f
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(logOutput, &slog.HandlerOptions{Level: level})))

	if *showVersion {
		fmt.Printf("tls-scanner %s (commit: %s)\n", version, commit)
		return 0
	}

	isPQCCheck = *pqcCheck

	if *generateTemplate != "" {
		if err := scanner.GenerateTemplate(*generateTemplate); err != nil {
			slog.Error("writing template", "error", err)
			return 1
		}
		fmt.Printf("Template written to %s\n", *generateTemplate)
		return 0
	}

	if *scanTimeoutPerTarget <= 0 || *connectTimeout <= 0 {
		fmt.Fprintln(os.Stderr, "Error: --scan-timeout-per-target and --connect-timeout must be positive integers")
		return 2
	}

	timeouts := scanner.ScanTimeouts{
		PerTargetSeconds: *scanTimeoutPerTarget,
		ConnectTimeout:   *connectTimeout,
	}

	starttlsPorts, err := scanner.ParseStarttlsPorts(*starttlsPortsFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 2
	}

	policy, err := scanner.Policy()
	if err != nil {
		slog.Error("loading policy", "error", err)
		return 1
	}

	var tlsProfileOverride *k8s.TLSSecurityProfile
	if *tlsProfileType != "" {
		tlsProfileOverride, err = k8s.NewTLSSecurityProfileFromType(*tlsProfileType)
		if err != nil {
			slog.Error("invalid tls profile type", "error", err)
			return 2
		}
	}

	defer func() {
		if *timingFile != "" {
			path := filepath.Join(*artifactDir, *timingFile)
			if err := timing.Timings.WriteReport(path); err != nil {
				slog.Warn("could not write timing report", "error", err)
			} else {
				slog.Info("timing report written", "path", path)
			}
		}
	}()

	if !*dryRun && !scanner.IsTestSSLInstalled() {
		slog.Error("testssl.sh is not installed or not in the system's PATH")
		return 1
	}

	if *concurrentScans == 0 {
		*concurrentScans = runtime.NumCPU()
		slog.Info("concurrency set from CPU count", "workers", *concurrentScans)
	} else if *concurrentScans < 0 {
		slog.Error("number of concurrent scans must be >= 0 (0 = auto)")
		return 1
	}

	var client *k8s.Client
	var pods []k8s.PodInfo

	if *targets != "" {
		targetList := strings.Split(*targets, ",")
		if len(targetList) == 0 || (len(targetList) == 1 && targetList[0] == "") {
			slog.Error("--targets flag provided but no targets were specified")
			return 1
		}

		var jobs []scanner.ScanJob
		for _, t := range targetList {
			hostValue, portValue, err := parseTarget(t)
			if err != nil {
				slog.Warn("skipping invalid target format", "target", t, "expected", "host:port")
				continue
			}
			jobs = append(jobs, scanner.ScanJob{IP: hostValue, Port: portValue})
		}

		if len(jobs) == 0 {
			slog.Error("no valid targets found in --targets flag")
			return 1
		}

		if *dryRun {
			output.PrintDryRunTargets(jobs)
			return 0
		}

		scanResults := scanner.Scan(jobs, *concurrentScans, nil, tlsProfileOverride, policy, timeouts, starttlsPorts)
		finalScanResults = &scanResults

		if err := output.WriteOutputFiles(scanResults, *artifactDir, *jsonFile, *csvFile, *junitFile, isPQCCheck); err != nil {
			slog.Error("writing output files", "error", err)
			return 1
		}
		if isPQCCheck {
			output.PrintPQCClusterResults(scanResults)
		} else if *jsonFile == "" && *csvFile == "" && *junitFile == "" {
			output.PrintClusterResults(scanResults)
		}

		return
	}

	if *templateFile != "" {
		jobs, err := scanner.LoadTemplate(*templateFile)
		if err != nil {
			slog.Error("loading template", "error", err)
			return 1
		}

		scanResults := scanner.Scan(jobs, *concurrentScans, nil, tlsProfileOverride, policy, timeouts, starttlsPorts)
		finalScanResults = &scanResults

		if err := output.WriteOutputFiles(scanResults, *artifactDir, *jsonFile, *csvFile, *junitFile, isPQCCheck); err != nil {
			slog.Error("writing output files", "error", err)
			return 1
		}
		if isPQCCheck {
			output.PrintPQCClusterResults(scanResults)
		} else if *jsonFile == "" && *csvFile == "" && *junitFile == "" {
			output.PrintClusterResults(scanResults)
		}

		return
	}

	if *allPods {
		client, err = k8s.NewClient()
		if err != nil {
			slog.Error("could not create kubernetes client for --all-pods", "error", err)
			return 1
		}

		pods, err = client.GetAllPodsInfo()
		if err != nil {
			slog.Error("listing pods", "error", err)
			return 1
		}
		pods = client.FilterPodsByComponent(pods, *componentFilter)
		pods = k8s.FilterPodsByNamespace(pods, *namespaceFilter)
		pods = k8s.FilterPodsByExcludeLabels(pods, *excludeLabels)

		if len(pods) == 0 {
			slog.Warn("no pods found matching the given filters, nothing to scan")
			return 0
		}

		slog.Info("pods to scan", "count", len(pods))

		if *limitIPs > 0 {
			totalIPs := 0
			for _, pod := range pods {
				totalIPs += len(pod.IPs)
			}

			if totalIPs > *limitIPs {
				slog.Info("limiting scan", "limit", *limitIPs, "found", totalIPs)
				pods = scanner.LimitPodsToIPCount(pods, *limitIPs)
				limitedTotal := 0
				for _, pod := range pods {
					limitedTotal += len(pod.IPs)
				}
				slog.Info("after limiting", "pods", len(pods), "ips", limitedTotal)
			}
		}
	}

	if len(pods) > 0 && *dryRun {
		discovery := scanner.DiscoverTargets(pods, *concurrentScans, client)
		output.PrintDryRunResults(discovery)
		return 0
	}

	if len(pods) > 0 {
		scanResults := scanner.PerformClusterScan(pods, *concurrentScans, client, policy, timeouts, tlsProfileOverride, starttlsPorts)
		finalScanResults = &scanResults

		if err := output.WriteOutputFiles(scanResults, *artifactDir, *jsonFile, *csvFile, *junitFile, isPQCCheck); err != nil {
			slog.Error("writing output files", "error", err)
			return 1
		}
		if isPQCCheck {
			output.PrintPQCClusterResults(scanResults)
		} else if *jsonFile == "" && *csvFile == "" && *junitFile == "" {
			output.PrintClusterResults(scanResults)
		}

		return
	}

	portNum, err := strconv.Atoi(*port)
	if err != nil {
		slog.Error("invalid port", "port", *port)
		return 1
	}

	jobs := []scanner.ScanJob{{IP: normalizeHost(*host), Port: portNum}}

	if *dryRun {
		output.PrintDryRunTargets(jobs)
		return 0
	}

	scanResults := scanner.Scan(jobs, *concurrentScans, client, tlsProfileOverride, policy, timeouts, starttlsPorts)
	finalScanResults = &scanResults

	if err := output.WriteOutputFiles(scanResults, *artifactDir, *jsonFile, *csvFile, *junitFile, isPQCCheck); err != nil {
		slog.Error("writing output files", "error", err)
		return 1
	}
	if isPQCCheck {
		output.PrintPQCClusterResults(scanResults)
	} else if *jsonFile == "" && *csvFile == "" && *junitFile == "" {
		output.PrintParsedResults(scanResults)
	}

	return
}

func parseTarget(target string) (string, int, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return "", 0, fmt.Errorf("empty target")
	}

	host, port, err := net.SplitHostPort(target)
	if err != nil {
		// Support unbracketed IPv6 targets by splitting on the last colon.
		// Example: fd2e:6f44:5dd8:c956::16:6385
		if strings.Count(target, ":") > 1 && !strings.HasPrefix(target, "[") {
			idx := strings.LastIndex(target, ":")
			if idx <= 0 || idx >= len(target)-1 {
				return "", 0, err
			}
			host = target[:idx]
			port = target[idx+1:]
		} else {
			return "", 0, err
		}
	}

	portNum, err := strconv.Atoi(port)
	if err != nil {
		return "", 0, err
	}

	return normalizeHost(host), portNum, nil
}

func normalizeHost(host string) string {
	host = strings.TrimSpace(host)
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") && len(host) >= 2 {
		return host[1 : len(host)-1]
	}
	return host
}
