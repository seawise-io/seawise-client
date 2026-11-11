package appsync

import (
	"context"
	"slices"
	"strings"
	"testing"

	pb "github.com/seawise-io/seawise-client/tunnelwire/tunnelpb"
)

func TestListTooLargeRetriedAtListPeriod(t *testing.T) {
	h := newHarness(t, app("A", "10.0.0.1", 80))
	h.api.push(status(413, map[string]string{"error": "list_too_large"}))
	d := h.e.Step(context.Background())
	s := h.e.Status()
	if d < DefaultListEvery || !strings.Contains(s.LastError, "too large") || s.LastResult != ResultRetrying {
		t.Fatalf("delay %v status %+v", d, s)
	}
	if s.OutboxDepth != 0 || s.Adopted || len(h.api.requests(pb.DeviceMethod_REGISTER_APPS)) != 0 {
		t.Fatalf("applied after a refused list: %+v", s)
	}
	if d := h.e.Step(context.Background()); d <= 0 || len(h.api.requests(pb.DeviceMethod_LIST_APPS)) != 1 {
		t.Fatalf("listed again before the list period: %v", d)
	}
	h.clk.Add(DefaultListEvery)
	h.settle(20)
	registeredOn(t, h.api, 1)
}

func TestDeleteAbsentUnrecordedNoted(t *testing.T) {
	a := app("A", "10.0.0.1", 80)
	h := newHarness(t, a)
	h.settle(20)
	if err := h.e.Remove(a.LocalID); err != nil {
		t.Fatal(err)
	}
	h.api.push(only(pb.DeviceMethod_DELETE_APPS, func(Request) (Response, error, bool, bool) {
		return jsonResp(200, map[string]any{"results": []map[string]any{{"local_id": a.LocalID, "id": nil, "result": "absent_unrecorded"}}}), nil, true, false
	}))
	h.e.Step(context.Background())
	s := h.e.Status()
	if s.OutboxDepth != 0 || slices.Contains(h.e.box.Registered, a.LocalID) || s.LastResult != ResultOK {
		t.Fatalf("delete not recorded: %+v", s)
	}
	if !slices.Contains(s.Notices, "delete_not_recorded_by_server:"+a.LocalID) {
		t.Fatalf("notices %v", s.Notices)
	}
}

func TestParseDeleteAnswerUnrecorded(t *testing.T) {
	a, b := "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", "bbbbbbbb-bbbb-4ccc-8ddd-eeeeeeeeeeee"
	raw := `{"results":[{"local_id":"` + a + `","result":"absent_unrecorded"},{"local_id":"` + b + `","result":"absent"}]}`
	got, err := parseDeleteAnswer([]byte(raw), []string{a, b})
	if err != nil || len(got) != 1 || got[0] != a {
		t.Fatalf("%v %v", got, err)
	}
}
