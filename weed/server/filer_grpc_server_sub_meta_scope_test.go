package weed_server

import (
	"testing"

	"github.com/seaweedfs/seaweedfs/weed/pb/filer_pb"
)

func ev(dir, name string) *filer_pb.SubscribeMetadataResponse {
	return &filer_pb.SubscribeMetadataResponse{
		Directory:         dir,
		TsNs:              1,
		EventNotification: &filer_pb.EventNotification{NewEntry: &filer_pb.Entry{Name: name}},
	}
}

func TestScopeMetadataResponse(t *testing.T) {
	prefixes := []string{"/buckets/uploads"}

	if got := scopeMetadataResponse(ev("/buckets/uploads/2026", "a.txt"), prefixes); got == nil {
		t.Error("an event under the prefix must pass")
	}
	if got := scopeMetadataResponse(ev("/buckets/other", "a.txt"), prefixes); got != nil {
		t.Error("an event outside the prefix must be dropped")
	}
	if got := scopeMetadataResponse(ev("/buckets/uploads-private", "a.txt"), prefixes); got != nil {
		t.Error("a sibling sharing the prefix's characters must be dropped")
	}

	// A rename from inside to outside, or the reverse, names a path outside.
	out := ev("/buckets/uploads", "a.txt")
	out.EventNotification.OldEntry = &filer_pb.Entry{Name: "a.txt"}
	out.EventNotification.NewParentPath = "/buckets/other"
	if got := scopeMetadataResponse(out, prefixes); got != nil {
		t.Error("a rename out of the scope must be dropped")
	}
	in := ev("/buckets/other", "a.txt")
	in.EventNotification.OldEntry = &filer_pb.Entry{Name: "a.txt"}
	in.EventNotification.NewParentPath = "/buckets/uploads"
	if got := scopeMetadataResponse(in, prefixes); got != nil {
		t.Error("a rename into the scope must be dropped")
	}

	// A heartbeat or position marker names no path and passes.
	if got := scopeMetadataResponse(&filer_pb.SubscribeMetadataResponse{TsNs: 5}, prefixes); got == nil {
		t.Error("a marker must pass")
	}

	// Log file references are never passed on, and a batch is filtered.
	batch := ev("/buckets/other", "x")
	batch.LogFileRefs = []*filer_pb.LogFileChunkRef{{}}
	batch.Events = []*filer_pb.SubscribeMetadataResponse{ev("/buckets/uploads", "ok"), ev("/etc", "secret")}
	got := scopeMetadataResponse(batch, prefixes)
	if got == nil || len(got.Events) != 1 || got.Events[0].Directory != "/buckets/uploads" || got.LogFileRefs != nil {
		t.Errorf("batch not filtered: %+v", got)
	}
	if got.EventNotification.GetNewEntry() != nil || got.EventNotification.GetOldEntry() != nil {
		t.Error("the out-of-scope head of a batch must be replaced by a marker")
	}
}
