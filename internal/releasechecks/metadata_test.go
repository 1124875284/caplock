package releasechecks

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func repositoryRoot(t *testing.T) string {
	t.Helper()
	root := filepath.Join("..", "..")
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("repository root: %v", err)
	}
	return root
}

func readRepoFile(t *testing.T, root string, parts ...string) string {
	t.Helper()
	path := filepath.Join(append([]string{root}, parts...)...)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}

func modulePath(t *testing.T, root string) string {
	t.Helper()
	for _, line := range strings.Split(readRepoFile(t, root, "go.mod"), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "module" {
			return fields[1]
		}
	}
	t.Fatal("go.mod has no module directive")
	return ""
}

func githubSlug(t *testing.T, module string) string {
	t.Helper()
	const prefix = "github.com/"
	if !strings.HasPrefix(module, prefix) {
		t.Fatalf("module %q is not a github.com path", module)
	}
	slug := strings.TrimPrefix(module, prefix)
	if strings.Count(slug, "/") != 1 {
		t.Fatalf("module %q does not identify a github owner/repository", module)
	}
	return slug
}

func parseYAMLMap(t *testing.T, name, value string) map[string]any {
	t.Helper()
	var document map[string]any
	if err := yaml.Unmarshal([]byte(value), &document); err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	if len(document) == 0 {
		t.Fatalf("%s is empty", name)
	}
	return document
}

func TestRepositoryMetadata(t *testing.T) {
	root := repositoryRoot(t)
	module := modulePath(t, root)
	slug := githubSlug(t, module)

	readme := readRepoFile(t, root, "README.md")
	for _, expected := range []string{
		"go install " + module + "/cmd/caplock@latest",
		"uses: " + slug + "@v0",
	} {
		if !strings.Contains(readme, expected) {
			t.Errorf("README.md is missing %q", expected)
		}
	}

	for _, file := range []string{".goreleaser.yaml", "Dockerfile"} {
		content := readRepoFile(t, root, file)
		expected := "-X " + module + "/internal/version.Version="
		if !strings.Contains(content, expected) {
			t.Errorf("%s is missing %q", file, expected)
		}
	}

	issueConfig := readRepoFile(t, root, ".github", "ISSUE_TEMPLATE", "config.yml")
	if !strings.Contains(issueConfig, "https://github.com/"+slug+"/") {
		t.Errorf("issue template links do not use repository slug %q", slug)
	}

	action := parseYAMLMap(t, "action.yml", readRepoFile(t, root, "action.yml"))
	runs, ok := action["runs"].(map[string]any)
	if !ok {
		t.Fatal("action.yml has no runs object")
	}
	if using, _ := runs["using"].(string); using != "composite" {
		t.Fatalf("action.yml runs.using = %q, want composite", using)
	}
	steps, ok := runs["steps"].([]any)
	if !ok || len(steps) == 0 {
		t.Fatal("action.yml has no composite steps")
	}
	for index, raw := range steps {
		step, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("action.yml step %d is not an object", index+1)
		}
		if _, hasRun := step["run"]; hasRun {
			if shell, _ := step["shell"].(string); strings.TrimSpace(shell) == "" {
				t.Errorf("action.yml run step %d has no shell", index+1)
			}
		}
	}

	workflowPaths, err := filepath.Glob(filepath.Join(root, ".github", "workflows", "*.yml"))
	if err != nil {
		t.Fatalf("list workflows: %v", err)
	}
	if len(workflowPaths) == 0 {
		t.Fatal("no GitHub workflows found")
	}
	sort.Strings(workflowPaths)
	for _, path := range workflowPaths {
		name := filepath.Base(path)
		workflow := parseYAMLMap(t, name, readRepoFile(t, root, ".github", "workflows", name))
		jobs, ok := workflow["jobs"].(map[string]any)
		if !ok || len(jobs) == 0 {
			t.Errorf("%s has no jobs", name)
			continue
		}
		for jobName, rawJob := range jobs {
			job, ok := rawJob.(map[string]any)
			if !ok {
				t.Errorf("%s job %q is not an object", name, jobName)
				continue
			}
			if _, reusable := job["uses"]; reusable {
				continue
			}
			if steps, ok := job["steps"].([]any); !ok || len(steps) == 0 {
				t.Errorf("%s job %q has no steps", name, jobName)
			}
		}
	}
}

func TestGoReleaserContract(t *testing.T) {
	root := repositoryRoot(t)
	module := modulePath(t, root)
	slug := githubSlug(t, module)
	config := parseYAMLMap(t, ".goreleaser.yaml", readRepoFile(t, root, ".goreleaser.yaml"))

	if got, _ := config["version"].(int); got != 2 {
		t.Errorf(".goreleaser.yaml version = %v, want 2", config["version"])
	}
	if got, _ := config["project_name"].(string); got != "caplock" {
		t.Errorf(".goreleaser.yaml project_name = %q, want caplock", got)
	}

	builds, ok := config["builds"].([]any)
	if !ok || len(builds) == 0 {
		t.Fatal(".goreleaser.yaml has no builds")
	}
	build, ok := builds[0].(map[string]any)
	if !ok {
		t.Fatal(".goreleaser.yaml build is not an object")
	}
	if got, _ := build["main"].(string); got != "./cmd/caplock" {
		t.Errorf("goreleaser build.main = %q, want ./cmd/caplock", got)
	}
	if got, _ := build["binary"].(string); got != "caplock" {
		t.Errorf("goreleaser build.binary = %q, want caplock", got)
	}
	if !stringListContains(build["goos"], "linux") || !stringListContains(build["goos"], "darwin") || !stringListContains(build["goos"], "windows") {
		t.Errorf("goreleaser goos = %v, want linux/darwin/windows", build["goos"])
	}
	if !stringListContains(build["goarch"], "amd64") || !stringListContains(build["goarch"], "arm64") {
		t.Errorf("goreleaser goarch = %v, want amd64/arm64", build["goarch"])
	}
	if !stringListContains(build["env"], "CGO_ENABLED=0") {
		t.Errorf("goreleaser build.env = %v, want CGO_ENABLED=0", build["env"])
	}
	if !listContainsSubstring(build["ldflags"], "-X "+module+"/internal/version.Version={{.Version}}") {
		t.Errorf("goreleaser ldflags = %v, want module version ldflag", build["ldflags"])
	}

	archives, ok := config["archives"].([]any)
	if !ok || len(archives) == 0 {
		t.Fatal(".goreleaser.yaml has no archives")
	}
	archive, ok := archives[0].(map[string]any)
	if !ok {
		t.Fatal(".goreleaser.yaml archive is not an object")
	}
	if !stringListContains(archive["formats"], "tar.gz") {
		t.Errorf("goreleaser archive formats = %v, want tar.gz", archive["formats"])
	}
	for _, file := range []string{"LICENSE", "NOTICE", "README.md", "CHANGELOG.md", "SECURITY.md", "schemas/*", "packs/*"} {
		if !containsString(archive["files"], file) {
			t.Errorf("goreleaser archive files missing %q", file)
		}
	}
	checksum, ok := config["checksum"].(map[string]any)
	if !ok || checksum["name_template"] != "checksums.txt" {
		t.Errorf("goreleaser checksum = %v, want checksums.txt", config["checksum"])
	}
	if sboms, ok := config["sboms"].([]any); !ok || len(sboms) == 0 {
		t.Error("goreleaser sboms is empty")
	}

	releaseStep := findStep(t, "release workflow", "release.yml", "goreleaser/goreleaser-action@v6", root)
	with, ok := releaseStep["with"].(map[string]any)
	if !ok || !strings.Contains(stringValue(with["args"]), "release --clean") {
		t.Errorf("goreleaser action args = %v, want release --clean", releaseStep["with"])
	}
	env, ok := releaseStep["env"].(map[string]any)
	if !ok || stringValue(env["GITHUB_TOKEN"]) == "" {
		t.Errorf("goreleaser action env = %v, want GITHUB_TOKEN", releaseStep["env"])
	}

	issueConfig := readRepoFile(t, root, ".github", "ISSUE_TEMPLATE", "config.yml")
	if !strings.Contains(issueConfig, "https://github.com/"+slug+"/") {
		t.Errorf("issue template links do not use repository slug %q", slug)
	}
}

func TestReleaseWorkflowContract(t *testing.T) {
	root := repositoryRoot(t)
	path := filepath.Join(root, ".github", "workflows", "release.yml")
	workflow := parseYAMLMap(t, "release.yml", readRepoFile(t, root, ".github", "workflows", "release.yml"))

	triggers, ok := workflow["on"].(map[string]any)
	if !ok {
		t.Fatal("release.yml has no on block")
	}
	push, ok := triggers["push"].(map[string]any)
	if !ok {
		t.Fatal("release.yml is not triggered by push")
	}
	if !containsString(push["tags"], "v*") {
		t.Errorf("release.yml push tags = %v, want v*", push["tags"])
	}
	permissions, ok := workflow["permissions"].(map[string]any)
	if !ok || permissions["contents"] != "write" {
		t.Errorf("release.yml permissions = %v, want contents: write", workflow["permissions"])
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("release workflow: %v", err)
	}
	if !strings.Contains(readRepoFile(t, root, ".github", "workflows", "release.yml"), "release --clean") {
		t.Error("release.yml does not run release --clean")
	}
}

func TestDockerfileContract(t *testing.T) {
	root := repositoryRoot(t)
	module := modulePath(t, root)
	dockerfile := readRepoFile(t, root, "Dockerfile")
	for _, expected := range []string{
		"AS build",
		"CGO_ENABLED=0",
		"go build -trimpath",
		"-X " + module + "/internal/version.Version=",
		"gcr.io/distroless/static-debian12:nonroot",
		"ENTRYPOINT [\"/usr/local/bin/caplock\"]",
	} {
		if !strings.Contains(dockerfile, expected) {
			t.Errorf("Dockerfile is missing %q", expected)
		}
	}
	if got := strings.Count(dockerfile, "\nFROM "); got < 2 {
		t.Errorf("Dockerfile has %d stages, want at least 2", got)
	}
}

func TestReleaseScriptsContract(t *testing.T) {
	root := repositoryRoot(t)
	for _, name := range []string{
		"clean-room.sh",
		"release-dry-run.sh",
		"security-negative.sh",
	} {
		path := filepath.Join(root, "scripts", name)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if !strings.HasPrefix(string(data), "#!/usr/bin/env bash\n") {
			t.Errorf("%s must start with a bash shebang", path)
		}
	}
	makefile := readRepoFile(t, root, "Makefile")
	for _, target := range []string{"release-check", "clean-room", "release-dry-run", "security-negative", "ci-e2e"} {
		if !strings.Contains(makefile, target+":") {
			t.Errorf("Makefile is missing target %q", target)
		}
	}
}

func findStep(t *testing.T, label, filename, action, root string) map[string]any {
	t.Helper()
	workflow := parseYAMLMap(t, filename, readRepoFile(t, root, ".github", "workflows", filename))
	jobs, ok := workflow["jobs"].(map[string]any)
	if !ok {
		t.Fatalf("%s has no jobs", label)
	}
	for _, rawJob := range jobs {
		job, ok := rawJob.(map[string]any)
		if !ok {
			continue
		}
		steps, _ := job["steps"].([]any)
		for _, rawStep := range steps {
			step, ok := rawStep.(map[string]any)
			if !ok {
				continue
			}
			if uses, _ := step["uses"].(string); uses == action {
				return step
			}
		}
	}
	t.Fatalf("%s has no step using %s", label, action)
	return nil
}

func stringListContains(value any, want string) bool {
	switch typed := value.(type) {
	case []any:
		for _, item := range typed {
			if stringValue(item) == want {
				return true
			}
		}
	case []string:
		for _, item := range typed {
			if item == want {
				return true
			}
		}
	}
	return false
}

func containsString(value any, want string) bool {
	switch typed := value.(type) {
	case []any:
		for _, item := range typed {
			if stringValue(item) == want {
				return true
			}
		}
	case []string:
		for _, item := range typed {
			if item == want {
				return true
			}
		}
	}
	return false
}

func listContainsSubstring(value any, want string) bool {
	switch typed := value.(type) {
	case []any:
		for _, item := range typed {
			if strings.Contains(stringValue(item), want) {
				return true
			}
		}
	case []string:
		for _, item := range typed {
			if strings.Contains(item, want) {
				return true
			}
		}
	}
	return false
}

func stringValue(value any) string {
	text, _ := value.(string)
	return text
}
