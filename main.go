package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// Finding represents a detected secret in a file
type Finding struct {
	File    string
	Line    int
	Pattern string
	Match   string
}

// GiteaRepo represents a repo from the Gitea API
type GiteaRepo struct {
	Name     string `json:"name"`
	CloneURL string `json:"clone_url"`
	Private  bool   `json:"private"`
}

// Define secret patterns to scan for
var patterns = map[string]*regexp.Regexp{
	"AWS Access Key":     regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	"AWS Secret Key":     regexp.MustCompile(`(?i)aws_secret_access_key\s*=\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?`),
	"Generic API Key":    regexp.MustCompile(`(?i)(api_key|apikey|api-key)\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{20,})['\"]?`),
	"Generic Secret":     regexp.MustCompile(`(?i)(secret|password|passwd|pwd)\s*[:=]\s*['\"]?([^\s'\"]{8,})['\"]?`),
	"GitHub Token":       regexp.MustCompile(`ghp_[A-Za-z0-9]{36}`),
	"GitHub OAuth":       regexp.MustCompile(`gho_[A-Za-z0-9]{36}`),
	"Private Key Header": regexp.MustCompile(`-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`),
	"Bearer Token":       regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9\-._~+/]+=*`),
	"Basic Auth in URL":  regexp.MustCompile(`https?://[^/\s]+:[^/\s@]+@[^/\s]+`),
	"Slack Token":        regexp.MustCompile(`xox[baprs]-[A-Za-z0-9-]+`),
	"Stripe Key":         regexp.MustCompile(`sk_live_[A-Za-z0-9]{24}`),
	"SendGrid Key":       regexp.MustCompile(`SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}`),
	"Database URL":       regexp.MustCompile(`(?i)(postgres|mysql|mongodb|redis):\/\/[^\s'"]+`),
}

// File extensions to skip
var skipExtensions = map[string]bool{
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true,
	".svg": true, ".ico": true, ".pdf": true, ".zip": true,
	".tar": true, ".gz": true, ".bin": true, ".exe": true,
	".mp4": true, ".mp3": true, ".woff": true, ".woff2": true,
	".ttf": true, ".eot": true,
}

// Directories to skip
var skipDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true,
	".venv": true, "__pycache__": true, ".idea": true,
	"dist": true, "build": true, "venv": true,
}

func scanFile(path string) ([]Finding, error) {
	var findings []Finding

	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		for patternName, re := range patterns {
			if match := re.FindString(line); match != "" {
				display := match
				if len(display) > 60 {
					display = display[:60] + "..."
				}
				findings = append(findings, Finding{
					File:    path,
					Line:    lineNum,
					Pattern: patternName,
					Match:   display,
				})
			}
		}
	}

	return findings, scanner.Err()
}

func scanDirectory(root string) ([]Finding, error) {
	var allFindings []Finding

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		base := filepath.Base(path)
		if strings.HasPrefix(base, ".") && info.IsDir() {
			return filepath.SkipDir
		}
		if info.IsDir() && skipDirs[base] {
			return filepath.SkipDir
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		if skipExtensions[strings.ToLower(filepath.Ext(path))] {
			return nil
		}

		findings, err := scanFile(path)
		if err != nil {
			return nil
		}
		allFindings = append(allFindings, findings...)
		return nil
	})

	return allFindings, err
}

func getGiteaRepos(giteaURL, token string) ([]GiteaRepo, error) {
	url := fmt.Sprintf("%s/api/v1/repos/search?limit=50&token=%s", giteaURL, token)
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result struct {
		Data []GiteaRepo `json:"data"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	return result.Data, nil
}

func scanGitea(giteaURL, token string) {
	fmt.Printf("\n🔍 NHI Scanner - Gitea Mode\n")
	fmt.Printf("   Server: %s\n", giteaURL)
	fmt.Println(strings.Repeat("─", 60))

	repos, err := getGiteaRepos(giteaURL, token)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error fetching repos: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Found %d repos to scan\n\n", len(repos))

	totalFindings := 0

	for _, repo := range repos {
		fmt.Printf("📦 Scanning %s...\n", repo.Name)

		// Create temp dir
		tmpDir, err := os.MkdirTemp("", "nhiscan-*")
		if err != nil {
			fmt.Printf("   ⚠️  Could not create temp dir: %v\n", err)
			continue
		}

		// Inject token into clone URL for auth
		cloneURL := strings.Replace(repo.CloneURL, "http://", fmt.Sprintf("http://scanner:%s@", token), 1)

		// Clone the repo
		cmd := exec.Command("git", "clone", "--depth=1", cloneURL, tmpDir)
		cmd.Stdout = io.Discard
		cmd.Stderr = io.Discard
		if err := cmd.Run(); err != nil {
			fmt.Printf("   ⚠️  Could not clone: %v\n", err)
			os.RemoveAll(tmpDir)
			continue
		}

		// Scan it
		findings, err := scanDirectory(tmpDir)
		if err != nil {
			fmt.Printf("   ⚠️  Scan error: %v\n", err)
			os.RemoveAll(tmpDir)
			continue
		}

		if len(findings) == 0 {
			fmt.Printf("   ✅ Clean\n\n")
		} else {
			fmt.Printf("   ⚠️  %d finding(s):\n", len(findings))
			for _, f := range findings {
				rel, _ := filepath.Rel(tmpDir, f.File)
				fmt.Printf("      Line %-4d [%s] %s\n", f.Line, f.Pattern, rel)
				fmt.Printf("             %s\n", f.Match)
			}
			fmt.Println()
			totalFindings += len(findings)
		}

		// Cleanup
		os.RemoveAll(tmpDir)
	}

	fmt.Println(strings.Repeat("─", 60))
	fmt.Printf("Total findings across all repos: %d\n\n", totalFindings)
}

func main() {
	// Gitea mode: go run main.go --gitea http://192.168.86.111:3200 YOUR_TOKEN
	if len(os.Args) == 4 && os.Args[1] == "--gitea" {
		scanGitea(os.Args[2], os.Args[3])
		return
	}

	// Local mode: go run main.go /path/to/dir
	scanPath := "."
	if len(os.Args) > 1 {
		scanPath = os.Args[1]
	}

	absPath, err := filepath.Abs(scanPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error resolving path: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\n🔍 NHI Scanner - Scanning: %s\n", absPath)
	fmt.Println(strings.Repeat("─", 60))

	findings, err := scanDirectory(absPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error scanning: %v\n", err)
		os.Exit(1)
	}

	if len(findings) == 0 {
		fmt.Println("✅ Clean - no secrets found.")
		return
	}

	byFile := make(map[string][]Finding)
	for _, f := range findings {
		byFile[f.File] = append(byFile[f.File], f)
	}

	fmt.Printf("⚠️  Found %d potential secret(s) in %d file(s):\n\n", len(findings), len(byFile))

	for file, fileFindings := range byFile {
		rel, _ := filepath.Rel(absPath, file)
		fmt.Printf("📄 %s\n", rel)
		for _, f := range fileFindings {
			fmt.Printf("   Line %-4d [%s]\n", f.Line, f.Pattern)
			fmt.Printf("          %s\n", f.Match)
		}
		fmt.Println()
	}

	fmt.Println(strings.Repeat("─", 60))
	fmt.Printf("Total: %d finding(s)\n\n", len(findings))
}
