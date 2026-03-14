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
	"sort"
	"strconv"
	"strings"
	"time"
)

type Finding struct {
	File    string
	Line    int
	Pattern string
	Match   string
}

type GiteaRepo struct {
	Name     string `json:"name"`
	CloneURL string `json:"clone_url"`
	Private  bool   `json:"private"`
}

type RepoResult struct {
	Name     string
	Findings []Finding
	Clean    bool
	Error    string
}

type ScanReport struct {
	Date    string
	Repos   []RepoResult
	Total   int
	RawText string
}

var patterns = map[string]*regexp.Regexp{
	"AWS Access Key":     regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	"AWS Secret Key":     regexp.MustCompile(`(?i)aws_secret_access_key\s*=\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?`),
	"Generic API Key":    regexp.MustCompile(`(?i)(api_key|apikey|api-key)\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{20,})['\"]?`),
	"Generic Secret":     regexp.MustCompile(`(?i)(secret|password|passwd|pwd)\s*[:=]\s*['\"]?([^\s'\"]{8,})['\"]?`),
	"GitHub Token":       regexp.MustCompile(`ghp_[A-Za-z0-9]{36}`),
	"GitHub OAuth":       regexp.MustCompile(`gho_[A-Za-z0-9]{36}`),
	"Private Key Header": regexp.MustCompile(`-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`),
	"Bearer Token":       regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9\-._~+/]+=*`), // nhiignore
	"Basic Auth in URL":  regexp.MustCompile(`https?://[^/\s]+:[^/\s@]+@[^/\s]+`),
	"Slack Token":        regexp.MustCompile(`xox[baprs]-[A-Za-z0-9-]+`),
	"Stripe Key":         regexp.MustCompile(`sk_live_[A-Za-z0-9]{24}`),
	"SendGrid Key":       regexp.MustCompile(`SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}`),
	"Database URL":       regexp.MustCompile(`(?i)(postgres|mysql|mongodb|redis):\/\/[^\s'"]+`),
}

var highRiskPatterns = map[string]bool{
	"AWS Access Key":     true,
	"AWS Secret Key":     true,
	"GitHub Token":       true,
	"GitHub OAuth":       true,
	"Private Key Header": true,
	"Stripe Key":         true,
}

var skipExtensions = map[string]bool{
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true,
	".svg": true, ".ico": true, ".pdf": true, ".zip": true,
	".tar": true, ".gz": true, ".bin": true, ".exe": true,
	".mp4": true, ".mp3": true, ".woff": true, ".woff2": true,
	".ttf": true, ".eot": true,
}

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

		if strings.HasSuffix(strings.TrimSpace(line), "// nhiignore") ||
			strings.HasSuffix(strings.TrimSpace(line), "# nhiignore") {
			continue
		}

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

func loadNHIIgnore(root string) []string {
	ignorePath := filepath.Join(root, ".nhiignore")
	content, err := os.ReadFile(ignorePath)
	if err != nil {
		return nil
	}
	var patterns []string
	for _, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		patterns = append(patterns, line)
	}
	return patterns
}

func isIgnored(path, root string, ignorePatterns []string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	for _, pattern := range ignorePatterns {
		matched, err := filepath.Match(pattern, rel)
		if err == nil && matched {
			return true
		}
		if strings.HasPrefix(rel, pattern) {
			return true
		}
	}
	return false
}

func scanDirectory(root string) ([]Finding, error) {
	var allFindings []Finding
	ignorePatterns := loadNHIIgnore(root)

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
		if isIgnored(path, root, ignorePatterns) {
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

func runScan(giteaURL, token string) []RepoResult {
	repos, err := getGiteaRepos(giteaURL, token)
	if err != nil {
		return nil
	}
	var results []RepoResult
	for _, repo := range repos {
		tmpDir, err := os.MkdirTemp("", "nhiscan-*")
		if err != nil {
			results = append(results, RepoResult{Name: repo.Name, Error: err.Error()})
			continue
		}
		cloneURL := strings.Replace(repo.CloneURL, "http://", fmt.Sprintf("http://scanner:%s@", token), 1) // nhiignore
		cmd := exec.Command("git", "clone", "--depth=1", cloneURL, tmpDir)
		cmd.Stdout = io.Discard
		cmd.Stderr = io.Discard
		if err := cmd.Run(); err != nil {
			results = append(results, RepoResult{Name: repo.Name, Error: "clone failed"})
			os.RemoveAll(tmpDir)
			continue
		}
		findings, _ := scanDirectory(tmpDir)
		os.RemoveAll(tmpDir)
		results = append(results, RepoResult{
			Name:     repo.Name,
			Findings: findings,
			Clean:    len(findings) == 0,
		})
	}
	return results
}

func parseReportFile(path string) ScanReport {
	content, err := os.ReadFile(path)
	if err != nil {
		return ScanReport{}
	}
	raw := string(content)
	base := filepath.Base(path)
	date := strings.TrimSuffix(strings.TrimPrefix(base, "nhi-"), ".txt")

	var repos []RepoResult
	var currentRepo *RepoResult
	total := 0

	for _, line := range strings.Split(raw, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "Scanning ") {
			name := strings.TrimPrefix(trimmed, "Scanning ")
			name = strings.TrimSuffix(strings.TrimSpace(name), "...")
			if currentRepo != nil {
				repos = append(repos, *currentRepo)
			}
			currentRepo = &RepoResult{Name: name, Clean: true}
		} else if currentRepo != nil && strings.Contains(trimmed, "finding(s):") {
			currentRepo.Clean = false
			parts := strings.Fields(trimmed)
			for _, p := range parts {
				if n, err := strconv.Atoi(p); err == nil {
					total += n
					break
				}
			}
		} else if currentRepo != nil && strings.Contains(trimmed, "[") && strings.Contains(trimmed, "]") {
			currentRepo.Findings = append(currentRepo.Findings, Finding{Match: trimmed})
		}
	}
	if currentRepo != nil {
		repos = append(repos, *currentRepo)
	}

	return ScanReport{Date: date, Repos: repos, Total: total, RawText: raw}
}

func loadReports(reportsDir string) []ScanReport {
	files, err := filepath.Glob(filepath.Join(reportsDir, "nhi-*.txt"))
	if err != nil || len(files) == 0 {
		return nil
	}
	sort.Sort(sort.Reverse(sort.StringSlice(files)))
	var reports []ScanReport
	for _, f := range files {
		reports = append(reports, parseReportFile(f))
	}
	return reports
}

const dashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="theme-color" content="#0f1117">
<title>NHI Scanner</title>
<link rel="manifest" href="/manifest.json">
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0f1117;color:#e2e8f0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;min-height:100vh;padding:0 0 4rem}
.header{background:#161b27;border-bottom:1px solid #1e2740;padding:1rem 1.5rem;display:flex;align-items:center;gap:.75rem;position:sticky;top:0;z-index:10}
.logo{width:28px;height:28px;background:#3b82f6;border-radius:6px;display:flex;align-items:center;justify-content:center;font-size:14px;font-weight:600;color:#fff;flex-shrink:0}
.header h1{font-size:16px;font-weight:600;color:#f1f5f9}
.header .sub{font-size:12px;color:#64748b;margin-left:auto}
.container{max-width:900px;margin:0 auto;padding:1.5rem 1rem}
.metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:.75rem;margin-bottom:1.5rem}
.metric{background:#161b27;border:1px solid #1e2740;border-radius:10px;padding:1rem}
.metric .label{font-size:11px;color:#64748b;text-transform:uppercase;letter-spacing:.05em;margin-bottom:.4rem}
.metric .value{font-size:26px;font-weight:600;color:#f1f5f9}
.metric.danger .value{color:#f87171}
.metric.success .value{color:#34d399}
.metric.warn .value{color:#fbbf24}
.section-title{font-size:12px;font-weight:600;color:#64748b;text-transform:uppercase;letter-spacing:.08em;margin:1.5rem 0 .75rem}
.alert-box{background:#1c1117;border:1px solid #7f1d1d;border-radius:10px;padding:1rem 1.25rem;margin-bottom:1.5rem}
.alert-title{font-size:13px;font-weight:600;color:#f87171;margin-bottom:.5rem;display:flex;align-items:center;gap:.5rem}
.alert-dot{width:8px;height:8px;background:#f87171;border-radius:50%;display:inline-block;flex-shrink:0}
.alert-item{font-size:12px;color:#fca5a5;padding:.2rem 0 .2rem 1.25rem}
.repo-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:.75rem;margin-bottom:1.5rem}
.repo-card{background:#161b27;border:1px solid #1e2740;border-radius:10px;padding:1rem 1.25rem}
.repo-card.has-findings{border-left:3px solid #f59e0b}
.repo-card.high-risk{border-left:3px solid #f87171}
.repo-card.clean{border-left:3px solid #34d399}
.repo-name{font-size:14px;font-weight:500;color:#f1f5f9;margin-bottom:.4rem}
.repo-status.clean{font-size:12px;color:#34d399}
.repo-status.warn{font-size:12px;color:#f59e0b}
.repo-status.danger{font-size:12px;color:#f87171}
.trend-chart{background:#161b27;border:1px solid #1e2740;border-radius:10px;padding:1.25rem;margin-bottom:1.5rem}
.chart-inner{display:flex;align-items:flex-end;gap:6px;height:80px;margin-top:.75rem}
.bar-wrap{display:flex;flex-direction:column;align-items:center;gap:4px;flex:1}
.bar{width:100%;background:#3b82f6;border-radius:3px 3px 0 0;min-height:3px}
.bar.zero{background:#1e2740}
.bar-label{font-size:9px;color:#64748b;white-space:nowrap}
.history{display:flex;flex-direction:column;gap:.5rem}
.history-item{background:#161b27;border:1px solid #1e2740;border-radius:8px;padding:.75rem 1rem;display:flex;align-items:center;justify-content:space-between;cursor:pointer}
.history-date{font-size:13px;color:#f1f5f9;font-weight:500}
.history-meta{font-size:12px;color:#64748b}
.badge{font-size:11px;padding:2px 8px;border-radius:4px;font-weight:500}
.badge.clean{background:#064e3b;color:#34d399}
.badge.warn{background:#451a03;color:#fbbf24}
.badge.danger{background:#450a0a;color:#f87171}
.raw-view{display:none;background:#0d1117;border:1px solid #1e2740;border-radius:10px;padding:1.25rem;margin-top:.5rem;font-family:monospace;font-size:12px;color:#94a3b8;white-space:pre-wrap;line-height:1.6;max-height:400px;overflow-y:auto}
.raw-view.open{display:block}
.close-btn{background:none;border:1px solid #1e2740;color:#94a3b8;padding:.4rem .8rem;border-radius:6px;cursor:pointer;font-size:12px;margin-top:.75rem;display:block}
.empty{text-align:center;color:#64748b;padding:3rem;font-size:14px}
</style>
</head>
<body>
<div class="header">
  <div class="logo">N</div>
  <h1>NHI Scanner</h1>
  <span class="sub" id="last-scan"></span>
</div>
<div class="container" id="app"><div class="empty">Loading...</div></div>
<script>
async function load() {
  const res = await fetch('/api/reports');
  const data = await res.json();
  render(data);
}

function render(data) {
  const app = document.getElementById('app');
  if (!data.reports || data.reports.length === 0) {
    app.innerHTML = '<div class="empty">No scan reports found yet. Reports appear after the nightly scan runs at 2am.</div>';
    return;
  }

  const latest = data.reports[0];
  document.getElementById('last-scan').textContent = 'Last scan: ' + (latest.date || 'unknown');

  const totalRepos = latest.repos ? latest.repos.length : 0;
  const cleanRepos = latest.repos ? latest.repos.filter(r => r.clean).length : 0;
  const highRisk = latest.high_risk_count || 0;

  let alertsHTML = '';
  if (highRisk > 0) {
    const items = (latest.high_risk_findings || []).map(f => '<div class="alert-item">' + esc(f) + '</div>').join('');
    alertsHTML = '<div class="alert-box"><div class="alert-title"><span class="alert-dot"></span>High-risk findings require immediate attention</div>' + items + '</div>';
  }

  const reposHTML = (latest.repos || []).map(r => {
    const cls = r.high_risk ? 'high-risk' : (r.clean ? 'clean' : 'has-findings');
    const sCls = r.high_risk ? 'danger' : (r.clean ? 'clean' : 'warn');
    const sTxt = r.clean ? 'Clean' : r.finding_count + ' finding(s)' + (r.high_risk ? ' — HIGH RISK' : '');
    return '<div class="repo-card ' + cls + '"><div class="repo-name">' + esc(r.name) + '</div><div class="repo-status ' + sCls + '">' + sTxt + '</div></div>';
  }).join('');

  const maxF = Math.max(...data.reports.map(r => r.total || 0), 1);
  const barsHTML = data.reports.slice(0, 14).reverse().map(r => {
    const h = Math.max(Math.round(((r.total || 0) / maxF) * 72), r.total > 0 ? 6 : 3);
    const d = (r.date || '').split('-').slice(1).join('/');
    return '<div class="bar-wrap"><div class="bar ' + (r.total === 0 ? 'zero' : '') + '" style="height:' + h + 'px" title="' + (r.total||0) + ' findings on ' + (r.date||'') + '"></div><div class="bar-label">' + d + '</div></div>';
  }).join('');

  const historyHTML = data.reports.map((r, i) => {
    const bCls = r.high_risk_count > 0 ? 'danger' : (r.total === 0 ? 'clean' : 'warn');
    const bTxt = r.total === 0 ? 'Clean' : r.total + ' findings';
    return '<div class="history-item" onclick="toggleRaw(' + i + ')">' +
      '<div><div class="history-date">' + esc(r.date||'Unknown') + '</div>' +
      '<div class="history-meta">' + (r.repos ? r.repos.length : 0) + ' repos scanned</div></div>' +
      '<span class="badge ' + bCls + '">' + bTxt + '</span></div>' +
      '<div class="raw-view" id="raw-' + i + '">' + esc(r.raw_text||'') +
      '<button class="close-btn" onclick="event.stopPropagation();toggleRaw(' + i + ')">Close</button></div>';
  }).join('');

  app.innerHTML =
    '<div class="metrics">' +
      '<div class="metric"><div class="label">Repos scanned</div><div class="value">' + totalRepos + '</div></div>' +
      '<div class="metric success"><div class="label">Clean</div><div class="value">' + cleanRepos + '</div></div>' +
      '<div class="metric ' + (latest.total > 0 ? 'warn' : 'success') + '"><div class="label">Total findings</div><div class="value">' + (latest.total||0) + '</div></div>' +
      '<div class="metric ' + (highRisk > 0 ? 'danger' : 'success') + '"><div class="label">High risk</div><div class="value">' + highRisk + '</div></div>' +
    '</div>' +
    alertsHTML +
    '<div class="section-title">Repo status — latest scan</div>' +
    '<div class="repo-grid">' + reposHTML + '</div>' +
    '<div class="section-title">Findings trend</div>' +
    '<div class="trend-chart"><div style="font-size:12px;color:#64748b">Findings per scan (last ' + data.reports.length + ' scans)</div><div class="chart-inner">' + barsHTML + '</div></div>' +
    '<div class="section-title">Report history</div>' +
    '<div class="history">' + historyHTML + '</div>';
}

function toggleRaw(i) {
  document.getElementById('raw-' + i).classList.toggle('open');
}

function esc(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

load();
</script>
</body>
</html>`

const manifestJSON = `{
  "name": "NHI Scanner",
  "short_name": "NHI",
  "start_url": "/",
  "display": "standalone",
  "background_color": "#0f1117",
  "theme_color": "#0f1117",
  "description": "Non-Human Identity secrets scanner dashboard",
  "icons": [
    {"src": "/icon-192.png", "sizes": "192x192", "type": "image/png"},
    {"src": "/icon-512.png", "sizes": "512x512", "type": "image/png"}
  ]
}`

func serveAPIReports(reportsDir string, w http.ResponseWriter, r *http.Request) {
	reports := loadReports(reportsDir)

	type RepoJSON struct {
		Name         string `json:"name"`
		Clean        bool   `json:"clean"`
		FindingCount int    `json:"finding_count"`
		HighRisk     bool   `json:"high_risk"`
	}
	type ReportJSON struct {
		Date             string     `json:"date"`
		Total            int        `json:"total"`
		Repos            []RepoJSON `json:"repos"`
		HighRiskCount    int        `json:"high_risk_count"`
		HighRiskFindings []string   `json:"high_risk_findings"`
		RawText          string     `json:"raw_text"`
	}

	var out []ReportJSON
	for _, rep := range reports {
		var repoJSON []RepoJSON
		highRiskCount := 0
		var highRiskFindings []string
		for _, repo := range rep.Repos {
			isHighRisk := false
			for _, f := range repo.Findings {
				if highRiskPatterns[f.Pattern] {
					isHighRisk = true
					highRiskCount++
					highRiskFindings = append(highRiskFindings, fmt.Sprintf("%s: %s (line %d)", repo.Name, f.Pattern, f.Line))
				}
			}
			repoJSON = append(repoJSON, RepoJSON{
				Name:         repo.Name,
				Clean:        repo.Clean,
				FindingCount: len(repo.Findings),
				HighRisk:     isHighRisk,
			})
		}
		out = append(out, ReportJSON{
			Date:             rep.Date,
			Total:            rep.Total,
			Repos:            repoJSON,
			HighRiskCount:    highRiskCount,
			HighRiskFindings: highRiskFindings,
			RawText:          rep.RawText,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"reports": out})
}

func serveDashboard(reportsDir string, port string) {
	fmt.Printf("\nNHI Scanner Dashboard\n")
	fmt.Printf("  Serving on http://0.0.0.0:%s\n", port)
	fmt.Printf("  Reports dir: %s\n\n", reportsDir)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, dashboardHTML)
	})
	http.HandleFunc("/manifest.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, manifestJSON)
	})
	http.HandleFunc("/api/reports", func(w http.ResponseWriter, r *http.Request) {
		serveAPIReports(reportsDir, w, r)
	})
	http.HandleFunc("/api/scan", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", 405)
			return
		}
		giteaURL := os.Getenv("GITEA_URL")
		token := os.Getenv("GITEA_TOKEN")
		if giteaURL == "" || token == "" {
			http.Error(w, "GITEA_URL and GITEA_TOKEN env vars required", 500)
			return
		}
		go func() {
			results := runScan(giteaURL, token)
			reportPath := filepath.Join(reportsDir, fmt.Sprintf("nhi-%s.txt", time.Now().Format("2006-01-02")))
			f, err := os.Create(reportPath)
			if err != nil {
				return
			}
			defer f.Close()
			total := 0
			fmt.Fprintf(f, "\nNHI Scanner - Gitea Mode\n")
			fmt.Fprintf(f, "  Server: %s\n", giteaURL)
			fmt.Fprintf(f, "%s\n", strings.Repeat("─", 60))
			fmt.Fprintf(f, "Found %d repos to scan\n\n", len(results))
			for _, res := range results {
				fmt.Fprintf(f, "Scanning %s...\n", res.Name)
				if res.Clean {
					fmt.Fprintf(f, "  Clean\n\n")
				} else {
					fmt.Fprintf(f, "  %d finding(s):\n", len(res.Findings))
					for _, fi := range res.Findings {
						fmt.Fprintf(f, "    Line %-4d [%s] %s\n", fi.Line, fi.Pattern, fi.File)
						fmt.Fprintf(f, "           %s\n", fi.Match)
					}
					fmt.Fprintln(f)
					total += len(res.Findings)
				}
			}
			fmt.Fprintf(f, "%s\n", strings.Repeat("─", 60))
			fmt.Fprintf(f, "Total findings: %d\n\n", total)
		}()
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"status":"scan started"}`)
	})

	if err := http.ListenAndServe(":"+port, nil); err != nil {
		fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
		os.Exit(1)
	}
}

func scanGitea(giteaURL, token string) {
	fmt.Printf("\nNHI Scanner - Gitea Mode\n")
	fmt.Printf("  Server: %s\n", giteaURL)
	fmt.Println(strings.Repeat("─", 60))
	repos, err := getGiteaRepos(giteaURL, token)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error fetching repos: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Found %d repos to scan\n\n", len(repos))
	totalFindings := 0
	for _, repo := range repos {
		fmt.Printf("Scanning %s...\n", repo.Name)
		tmpDir, err := os.MkdirTemp("", "nhiscan-*")
		if err != nil {
			fmt.Printf("  Could not create temp dir: %v\n", err)
			continue
		}
		cloneURL := strings.Replace(repo.CloneURL, "http://", fmt.Sprintf("http://scanner:%s@", token), 1) // nhiignore
		cmd := exec.Command("git", "clone", "--depth=1", cloneURL, tmpDir)
		cmd.Stdout = io.Discard
		cmd.Stderr = io.Discard
		if err := cmd.Run(); err != nil {
			fmt.Printf("  Could not clone\n")
			os.RemoveAll(tmpDir)
			continue
		}
		findings, _ := scanDirectory(tmpDir)
		os.RemoveAll(tmpDir)
		if len(findings) == 0 {
			fmt.Printf("  Clean\n\n")
		} else {
			fmt.Printf("  %d finding(s):\n", len(findings))
			for _, f := range findings {
				rel, _ := filepath.Rel(tmpDir, f.File)
				fmt.Printf("    Line %-4d [%s] %s\n", f.Line, f.Pattern, rel)
				fmt.Printf("           %s\n", f.Match)
			}
			fmt.Println()
			totalFindings += len(findings)
		}
	}
	fmt.Println(strings.Repeat("─", 60))
	fmt.Printf("Total findings across all repos: %d\n\n", totalFindings)
}

func main() {
	if len(os.Args) >= 2 && os.Args[1] == "--serve" {
		port := "3300"
		reportsDir := "/home/gus/reports"
		if len(os.Args) >= 3 {
			port = os.Args[2]
		}
		if len(os.Args) >= 4 {
			reportsDir = os.Args[3]
		}
		serveDashboard(reportsDir, port)
		return
	}
	if len(os.Args) == 4 && os.Args[1] == "--gitea" {
		scanGitea(os.Args[2], os.Args[3])
		return
	}
	scanPath := "."
	if len(os.Args) > 1 {
		scanPath = os.Args[1]
	}
	absPath, err := filepath.Abs(scanPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error resolving path: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("\nNHI Scanner - Scanning: %s\n", absPath)
	fmt.Println(strings.Repeat("─", 60))
	findings, err := scanDirectory(absPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error scanning: %v\n", err)
		os.Exit(1)
	}
	if len(findings) == 0 {
		fmt.Println("Clean - no secrets found.")
		return
	}
	byFile := make(map[string][]Finding)
	for _, f := range findings {
		byFile[f.File] = append(byFile[f.File], f)
	}
	fmt.Printf("Found %d potential secret(s) in %d file(s):\n\n", len(findings), len(byFile))
	for file, fileFindings := range byFile {
		rel, _ := filepath.Rel(absPath, file)
		fmt.Printf("%s\n", rel)
		for _, f := range fileFindings {
			fmt.Printf("  Line %-4d [%s]\n", f.Line, f.Pattern)
			fmt.Printf("         %s\n", f.Match)
		}
		fmt.Println()
	}
	fmt.Println(strings.Repeat("─", 60))
	fmt.Printf("Total: %d finding(s)\n\n", len(findings))
}
