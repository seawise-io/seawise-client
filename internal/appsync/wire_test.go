package appsync

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestCheckAppBounds(t *testing.T) {
	ok := []struct {
		name, host string
		port       int
		icon       string
	}{
		{strings.Repeat("é", maxName), strings.Repeat("a", maxHost), 1, strings.Repeat("a", maxIcon)},
		{"a", "[::1]", 65535, " ~"},
	}
	for _, c := range ok {
		if err := checkApp(c.name, c.host, c.port, c.icon); err != nil {
			t.Fatalf("%q: %v", c.name, err)
		}
	}
	bad := []struct {
		name, host string
		port       int
		icon       string
	}{
		{strings.Repeat("a", maxName+1), "h", 1, ""},
		{"a", strings.Repeat("a", maxHost+1), 1, ""},
		{"a", "h", 0, ""},
		{"a", "h", 65536, ""},
		{"a", "h", 1, strings.Repeat("a", maxIcon+1)},
		{"a", "h", 1, "\x1f"},
		{"a", "h", 1, "\x7f"},
		{"\xff", "h", 1, ""},
	}
	for _, c := range bad {
		if checkApp(c.name, c.host, c.port, c.icon) == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
}

func TestTransientStatus(t *testing.T) {
	for code, want := range map[int]bool{200: false, 299: false, 300: true, 399: true, 400: false, 403: false, 408: true, 409: false, 429: true, 499: false, 500: true, 503: true} {
		if transientStatus(code) != want {
			t.Fatalf("%d: want %v", code, want)
		}
	}
}

func listApp(i int, mod func(map[string]any)) map[string]any {
	a := map[string]any{"id": fmt.Sprintf("aaaaaaaa-0000-4000-8000-%012d", i), "local_id": fmt.Sprintf("bbbbbbbb-0000-4000-8000-%012d", i),
		"name": "n", "host": "h", "port": 1, "subdomain": "s", "public_requested": true}
	if mod != nil {
		mod(a)
	}
	return a
}

func listBody(apps []map[string]any, del []string) []byte {
	if del == nil {
		del = []string{}
	}
	if apps == nil {
		apps = []map[string]any{}
	}
	b, _ := json.Marshal(map[string]any{"apps": apps, "deleted": del})
	return b
}

func TestParseListBounds(t *testing.T) {
	apps := make([]map[string]any, maxListApps)
	for i := range apps {
		apps[i] = listApp(i, nil)
	}
	l, err := parseList(listBody(apps, nil))
	if err != nil || len(l.Apps) != maxListApps || !l.Apps[0].PublicRequested || l.Apps[0].LocalID == "" {
		t.Fatal(err)
	}
	if _, err := parseList(listBody(append(apps, listApp(maxListApps, nil)), nil)); err == nil {
		t.Fatal("too many apps accepted")
	}
	del := make([]string, maxListDel)
	for i := range del {
		del[i] = fmt.Sprintf("cccccccc-0000-4000-8000-%012d", i)
	}
	if _, err := parseList(listBody(nil, del)); err != nil {
		t.Fatal(err)
	}
	if _, err := parseList(listBody(nil, append(del, "dddddddd-0000-4000-8000-000000000000"))); err == nil {
		t.Fatal("too many deleted accepted")
	}
	good := []func(map[string]any){
		func(a map[string]any) { a["name"] = strings.Repeat("a", 4*maxName) },
		func(a map[string]any) { a["host"] = strings.Repeat("a", maxHost) },
		func(a map[string]any) { a["port"] = 65535 },
		func(a map[string]any) { a["local_id"] = nil; delete(a, "public_requested") },
	}
	for i, m := range good {
		if _, err := parseList(listBody([]map[string]any{listApp(1, m)}, nil)); err != nil {
			t.Fatalf("good %d: %v", i, err)
		}
	}
	bad := []func(map[string]any){
		func(a map[string]any) { a["name"] = strings.Repeat("a", 4*maxName+1) },
		func(a map[string]any) { a["host"] = strings.Repeat("a", maxHost+1) },
		func(a map[string]any) { a["port"] = 0 },
		func(a map[string]any) { a["port"] = 65536 },
		func(a map[string]any) { a["subdomain"] = "Bad" },
		func(a map[string]any) { a["id"] = "x" },
		func(a map[string]any) { a["local_id"] = "x" },
		func(a map[string]any) { delete(a, "host") },
	}
	for i, m := range bad {
		if _, err := parseList(listBody([]map[string]any{listApp(1, m)}, nil)); err == nil {
			t.Fatalf("bad %d accepted", i)
		}
	}
	if _, err := parseList(listBody([]map[string]any{listApp(1, nil), listApp(2, func(a map[string]any) { a["local_id"] = "bbbbbbbb-0000-4000-8000-000000000001" })}, nil)); err == nil {
		t.Fatal("repeated local_id accepted")
	}
}

func TestParseErrorBounds(t *testing.T) {
	if e := parseError([]byte(`{"error":"` + strings.Repeat("a", 64) + `","code":"` + strings.Repeat("b", 64) + `"}`)); e.Error == "" || e.Code == "" {
		t.Fatal("64-byte fields dropped")
	}
	for _, raw := range []string{`{"error":"` + strings.Repeat("a", 65) + `"}`, `{"code":"` + strings.Repeat("a", 65) + `"}`, `{"error":"x","local_id":"bad"}`, `nope`} {
		if e := parseError([]byte(raw)); e.Error != "" || e.Code != "" {
			t.Fatalf("%s parsed", raw)
		}
	}
}

func TestParseRegisterAnswerRefuses(t *testing.T) {
	lid := "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
	for _, raw := range []string{
		`{"items":[]}`,
		`{"items":null}`,
		`{"items":[{"local_id":"` + lid + `","id":"` + lid + `","result":"created","subdomain":"Bad"}]}`,
		`{"items":[{"local_id":"` + lid + `","id":null,"result":"created","subdomain":"a"}]}`,
		`{"items":[{"local_id":"` + lid + `","id":"` + lid + `","result":"deleted","subdomain":null}]}`,
		`{"items":[{"local_id":"` + lid + `","id":"` + lid + `","result":"other","subdomain":"a"}]}`,
		`{"items":[{"local_id":"bbbbbbbb-bbbb-4ccc-8ddd-eeeeeeeeeeee","id":"` + lid + `","result":"created","subdomain":"a"}]}`,
	} {
		if _, err := parseRegisterAnswer([]byte(raw), []string{lid}); err == nil {
			t.Fatalf("%s accepted", raw)
		}
	}
	for _, raw := range []string{`{"results":[]}`, `{"results":[{"local_id":"` + lid + `","result":"created"}]}`} {
		if _, err := parseDeleteAnswer([]byte(raw), []string{lid}); err == nil {
			t.Fatalf("%s accepted", raw)
		}
	}
}
