package output

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/openshift/tls-scanner/internal/scanner"
)

func WriteJSONOutput(data interface{}, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(data); err != nil {
		return fmt.Errorf("failed to encode JSON: %w", err)
	}

	slog.Info("JSON output written", "path", filename)
	return nil
}

func WriteOutputFiles(results scanner.ScanResults, artifactDir, jsonFile, csvFile, junitFile, attestationFile string, pqcCheck bool, meta *AttestationMeta) error {
	if jsonFile == "" && csvFile == "" && junitFile == "" && attestationFile == "" {
		return nil
	}

	if err := os.MkdirAll(artifactDir, 0755); err != nil {
		return fmt.Errorf("could not create artifact directory %s: %w", artifactDir, err)
	}
	slog.Info("artifacts directory created", "path", artifactDir)

	if jsonFile != "" {
		jsonPath := resolveOutputPath(artifactDir, jsonFile)
		if err := WriteJSONOutput(results, jsonPath); err != nil {
			slog.Error("writing JSON output", "error", err)
		} else {
			slog.Info("JSON results written", "path", jsonPath)
		}
	}

	if csvFile != "" {
		csvPath := resolveOutputPath(artifactDir, csvFile)
		if err := WriteCSVOutput(results, csvPath); err != nil {
			slog.Error("writing CSV output", "error", err)
		} else {
			slog.Info("CSV results written", "path", csvPath)
		}

		if len(results.ScanErrors) > 0 {
			errorFilename := strings.TrimSuffix(csvPath, filepath.Ext(csvPath)) + "_errors.csv"
			if err := WriteScanErrorsCSV(results, errorFilename); err != nil {
				slog.Error("writing scan errors CSV", "error", err)
			} else {
				slog.Info("scan errors written", "path", errorFilename)
			}
		}
	}

	if junitFile != "" {
		junitPath := resolveOutputPath(artifactDir, junitFile)
		if err := WriteJUnitOutput(results, junitPath, pqcCheck); err != nil {
			slog.Error("writing JUnit XML output", "error", err)
		} else {
			slog.Info("JUnit XML results written", "path", junitPath)
		}
	}

	if attestationFile != "" {
		attestationPath := resolveOutputPath(artifactDir, attestationFile)
		attMeta := AttestationMeta{}
		if meta != nil {
			attMeta = *meta
		}
		if err := WriteAttestationFile(results, attestationPath, pqcCheck, attMeta); err != nil {
			slog.Error("writing attestation output", "error", err)
		}
	}

	return nil
}
