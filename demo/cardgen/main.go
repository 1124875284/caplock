// Command cardgen renders the real CLI output captured by demo/run.sh into
// standalone HTML review cards and a local gallery.
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type scenario struct {
	ID            string
	Title         string
	Description   string
	Group         string
	Command       string
	Stdout        string
	Stderr        string
	ExitCode      int
	ExpectedExit  int
	Expected      bool
	Unexpected    bool
	HasStdout     bool
	HasStderr     bool
	StdoutLines   int
	StderrLines   int
	ScreenshotURL string
}

func main() {
	output := flag.String("output", "demo/output", "directory containing captured scenarios")
	screenshots := flag.String("screenshots", "demo/screenshots", "directory containing generated screenshots")
	flag.Parse()

	entries, err := os.ReadDir(*output)
	if err != nil {
		fatalf("read demo output: %v", err)
	}
	scenarios := make([]scenario, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() || entry.Name() == "bin" {
			continue
		}
		path := filepath.Join(*output, entry.Name())
		value, err := readScenario(path)
		if errors.Is(err, errNotScenario) {
			continue
		}
		if err != nil {
			fatalf("read scenario %s: %v", entry.Name(), err)
		}
		if _, err := os.Stat(filepath.Join(*screenshots, value.ID+".png")); err == nil {
			value.ScreenshotURL = "../screenshots/" + value.ID + ".png"
		}
		if err := writeCard(filepath.Join(path, "card.html"), value); err != nil {
			fatalf("render %s: %v", value.ID, err)
		}
		scenarios = append(scenarios, value)
	}
	sort.Slice(scenarios, func(i, j int) bool { return scenarios[i].ID < scenarios[j].ID })
	if len(scenarios) == 0 {
		fatalf("no captured scenarios found in %s", *output)
	}
	if err := writeGallery(filepath.Join(*output, "index.html"), scenarios); err != nil {
		fatalf("render gallery: %v", err)
	}
	fmt.Printf("rendered %d scenario cards and %s\n", len(scenarios), filepath.Join(*output, "index.html"))
}

var errNotScenario = errors.New("not a captured scenario")

func readScenario(path string) (scenario, error) {
	title, err := readText(path, "title.txt")
	if errors.Is(err, os.ErrNotExist) {
		return scenario{}, errNotScenario
	}
	if err != nil {
		return scenario{}, err
	}
	// Keep the literal reads explicit so a missing optional file remains an
	// empty presentation value rather than a generation failure.
	description, _ := readText(path, "description.txt")
	group, _ := readText(path, "group.txt")
	command, _ := readText(path, "command.txt")
	stdout, _ := readText(path, "stdout.txt")
	stderr, _ := readText(path, "stderr.txt")
	exitCode, err := readInt(path, "exit-code.txt")
	if err != nil {
		return scenario{}, err
	}
	expectedExit, err := readInt(path, "expected-exit.txt")
	if err != nil {
		return scenario{}, err
	}
	stdout = trimOutput(stdout)
	stderr = trimOutput(stderr)
	value := scenario{
		ID:           filepath.Base(path),
		Title:        strings.TrimSpace(title),
		Description:  strings.TrimSpace(description),
		Group:        strings.TrimSpace(group),
		Command:      trimOutput(command),
		Stdout:       stdout,
		Stderr:       stderr,
		ExitCode:     exitCode,
		ExpectedExit: expectedExit,
		Expected:     exitCode == expectedExit,
		HasStdout:    strings.TrimSpace(stdout) != "",
		HasStderr:    strings.TrimSpace(stderr) != "",
		StdoutLines:  lineCount(stdout),
		StderrLines:  lineCount(stderr),
	}
	value.Unexpected = !value.Expected
	return value, nil
}

func readText(path, name string) (string, error) {
	// #nosec G304 -- cardgen only reads files under the explicit demo output directory.
	data, err := os.ReadFile(filepath.Join(path, name))
	if err != nil {
		return "", err
	}
	return sanitize(string(data)), nil
}

func readInt(path, name string) (int, error) {
	value, err := readText(path, name)
	if err != nil {
		return 0, err
	}
	parsed, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil {
		return 0, fmt.Errorf("parse %s: %w", name, err)
	}
	return parsed, nil
}

func trimOutput(value string) string {
	return strings.TrimRight(value, "\r\n")
}

func lineCount(value string) int {
	if value == "" {
		return 0
	}
	return strings.Count(value, "\n") + 1
}

func sanitize(value string) string {
	return strings.Map(func(character rune) rune {
		if character == '\n' || character == '\t' || character >= ' ' {
			return character
		}
		return '�'
	}, value)
}

func writeCard(path string, value scenario) error {
	var buffer bytes.Buffer
	if err := cardTemplate.Execute(&buffer, value); err != nil {
		return err
	}
	return os.WriteFile(path, buffer.Bytes(), 0o600)
}

func writeGallery(path string, scenarios []scenario) error {
	var buffer bytes.Buffer
	if err := galleryTemplate.Execute(&buffer, scenarios); err != nil {
		return err
	}
	return os.WriteFile(path, buffer.Bytes(), 0o600)
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "cardgen: "+format+"\n", args...)
	os.Exit(1)
}

var cardTemplate = template.Must(template.New("card").Funcs(template.FuncMap{
	"status": func(value scenario) string {
		if value.Expected && value.ExitCode == 0 {
			return "PASS"
		}
		if value.Expected {
			return "GATE FIRED"
		}
		return "UNEXPECTED"
	},
	"statusClass": func(value scenario) string {
		if value.Expected && value.ExitCode == 0 {
			return "pass"
		}
		if value.Expected {
			return "gate"
		}
		return "fail"
	},
	"plural": func(count int, singular string) string {
		if count == 1 {
			return fmt.Sprintf("%d %s", count, singular)
		}
		return fmt.Sprintf("%d %ss", count, singular)
	},
}).Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Caplock demo · {{.Title}}</title>
<style>
:root{color-scheme:dark;--bg:#071017;--panel:#0c1821;--line:#1e3645;--text:#e8f1f4;--muted:#8da6b3;--cyan:#54d6c5;--green:#5ee08f;--amber:#f1bd63;--red:#ff7b82;--code:#08131b}
*{box-sizing:border-box}html,body{margin:0;min-height:100%;background:var(--bg);color:var(--text)}
body{font-family:Inter,ui-sans-serif,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:radial-gradient(circle at 18% 0%,rgba(84,214,197,.13),transparent 33%),radial-gradient(circle at 88% 12%,rgba(88,142,255,.12),transparent 34%),var(--bg)}
.page{width:min(1180px,calc(100% - 56px));margin:0 auto;padding:34px 0 44px}
.eyebrow{display:flex;justify-content:space-between;align-items:center;color:var(--muted);font-size:12px;letter-spacing:.16em;text-transform:uppercase;margin-bottom:18px}
.brand{display:flex;align-items:center;gap:10px;color:var(--cyan);font-weight:700;letter-spacing:.12em}.mark{width:11px;height:11px;border-radius:3px;background:var(--cyan);box-shadow:0 0 24px rgba(84,214,197,.7)}
.card{overflow:hidden;border:1px solid var(--line);border-radius:18px;background:linear-gradient(180deg,rgba(16,35,47,.96),rgba(8,19,27,.98));box-shadow:0 28px 80px rgba(0,0,0,.38)}
.hero{display:flex;gap:24px;justify-content:space-between;align-items:flex-start;padding:28px 30px 22px;border-bottom:1px solid var(--line);background:linear-gradient(125deg,rgba(84,214,197,.07),transparent 46%)}
h1{font-size:30px;line-height:1.18;letter-spacing:-.025em;margin:7px 0 9px;max-width:850px}.group{color:var(--cyan);font-size:12px;font-weight:700;letter-spacing:.14em;text-transform:uppercase}.description{color:var(--muted);font-size:15px;line-height:1.55;margin:0;max-width:850px}
.status{flex:none;display:flex;gap:9px;align-items:center;border:1px solid var(--line);border-radius:999px;padding:9px 13px;background:#09151d;font-size:12px;font-weight:700;letter-spacing:.08em}.dot{width:8px;height:8px;border-radius:50%}.pass .dot{background:var(--green);box-shadow:0 0 15px rgba(94,224,143,.8)}.pass{color:var(--green)}.gate .dot{background:var(--amber);box-shadow:0 0 15px rgba(241,189,99,.8)}.gate{color:var(--amber)}.fail .dot{background:var(--red);box-shadow:0 0 15px rgba(255,123,130,.8)}.fail{color:var(--red)}
.body{padding:24px 30px 30px}.label{display:flex;justify-content:space-between;align-items:center;margin:0 0 8px;color:var(--muted);font-size:11px;font-weight:700;letter-spacing:.13em;text-transform:uppercase}.meta{font-weight:500;letter-spacing:0;text-transform:none;color:#6f8997}
.command,.output{border:1px solid var(--line);border-radius:12px;background:var(--code);overflow:auto}
.command{padding:14px 17px;margin-bottom:20px;color:#c7f7ef;font:500 13px/1.65 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;white-space:pre-wrap;word-break:break-word}
.command::before{content:"$ ";color:var(--cyan)}
.output{padding:17px 18px;color:#d6e5ea;font:500 12.5px/1.62 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;white-space:pre;tab-size:4;min-height:54px}
.output.stderr{color:#f1d6a7;border-color:#514127;background:#171309;margin-top:12px}.empty{color:#6f8997;font-style:italic}
.footer{display:flex;justify-content:space-between;gap:20px;padding-top:18px;color:#67818e;font-size:11px}.footer strong{color:#94b1bd;font-weight:600}
</style>
</head>
<body><main class="page">
<div class="eyebrow"><span class="brand"><i class="mark"></i>CAPLOCK / VERIFICATION</span><span>{{.ID}}</span></div>
<section class="card">
<header class="hero"><div><div class="group">{{.Group}}</div><h1>{{.Title}}</h1><p class="description">{{.Description}}</p></div><div class="status {{statusClass .}}"><i class="dot"></i>{{status .}}</div></header>
<div class="body">
<div class="label"><span>Command</span><span class="meta">exit {{.ExitCode}} · expected {{.ExpectedExit}}</span></div>
<pre class="command">{{.Command}}</pre>
<div class="label"><span>Real CLI output</span><span class="meta">{{plural .StdoutLines "line"}}</span></div>
{{if .HasStdout}}<pre class="output">{{.Stdout}}</pre>{{else}}<pre class="output empty">(no stdout)</pre>{{end}}
{{if .HasStderr}}<div class="label" style="margin-top:16px"><span>stderr</span><span class="meta">{{plural .StderrLines "line"}}</span></div><pre class="output stderr">{{.Stderr}}</pre>{{end}}
<div class="footer"><span>Generated from the checked-in demo fixtures with the real Caplock binary.</span><span><strong>No deployment</strong> · local-only</span></div>
</div></section></main></body></html>`))

var galleryTemplate = template.Must(template.New("gallery").Funcs(template.FuncMap{
	"statusClass": func(value scenario) string {
		if value.Expected && value.ExitCode == 0 {
			return "pass"
		}
		if value.Expected {
			return "gate"
		}
		return "fail"
	},
}).Parse(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Caplock demo gallery</title><style>
:root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;background:#071017;color:#e8f1f4;font-family:Inter,ui-sans-serif,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}.wrap{width:min(1280px,calc(100% - 48px));margin:auto;padding:40px 0}h1{font-size:38px;letter-spacing:-.03em;margin:0 0 8px}p{color:#8da6b3;margin:0 0 32px}.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:18px}a{color:inherit;text-decoration:none}.item{border:1px solid #1e3645;border-radius:14px;background:#0c1821;overflow:hidden;transition:.15s border-color,transform}.item:hover{border-color:#54d6c5;transform:translateY(-2px)}.copy{padding:16px 18px}.id{color:#54d6c5;font:600 11px ui-monospace,Menlo,monospace;letter-spacing:.1em}.title{font-size:17px;font-weight:700;margin:6px 0 0}.tag{float:right;font-size:11px;font-weight:700}.pass{color:#5ee08f}.gate{color:#f1bd63}.fail{color:#ff7b82}img{display:block;width:100%;height:auto;border-bottom:1px solid #1e3645;background:#08131b}.placeholder{padding:35px 18px;text-align:center;color:#6f8997;font-size:12px;border-bottom:1px solid #1e3645}@media(max-width:800px){.grid{grid-template-columns:1fr}}
</style></head><body><div class="wrap"><h1>Caplock verification gallery</h1><p>Every card below is rendered from captured CLI stdout/stderr and the real exit code. Run <code>demo/run.sh</code>, then <code>demo/screenshots.sh</code>.</p><div class="grid">{{range .}}<a href="{{.ID}}/card.html"><article class="item">{{if .ScreenshotURL}}<img src="{{.ScreenshotURL}}" alt="{{.Title}}">{{else}}<div class="placeholder">Screenshot not generated yet</div>{{end}}<div class="copy"><span class="id">{{.ID}}</span><span class="tag {{statusClass .}}">exit {{.ExitCode}}</span><div class="title">{{.Title}}</div></div></article></a>{{end}}</div></div></body></html>`))
