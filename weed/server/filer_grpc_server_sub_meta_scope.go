package weed_server

import (
	"context"

	"github.com/seaweedfs/seaweedfs/weed/pb/filer_pb"
	"github.com/seaweedfs/seaweedfs/weed/security"
	"github.com/seaweedfs/seaweedfs/weed/util"
)

// metadataSubscriptionScope authorizes a SubscribeMetadata or
// SubscribeLocalMetadata call. A nil scope means the caller is unrestricted.
func (fs *FilerServer) metadataSubscriptionScope(ctx context.Context, method string) ([]string, error) {
	v := util.GetViper()
	return security.CheckGrpcMetadataSubscription(ctx,
		security.SigningKey(v.GetString("jwt.filer_signing.subscribe.key")),
		security.SigningKey(v.GetString("jwt.filer_signing.key")),
		method)
}

// scopeMetadataResponse keeps only what a scoped subscriber may see. An event
// is delivered only when every path it names is in scope, so a rename across
// the boundary never tells the subscriber the name on the other side. It
// returns nil when nothing is left to send.
func scopeMetadataResponse(resp *filer_pb.SubscribeMetadataResponse, prefixes []string) *filer_pb.SubscribeMetadataResponse {
	if resp == nil {
		return nil
	}
	// Log file chunk references would hand over whole logs, including events
	// outside the scope; the request never asks for them (see below).
	resp.LogFileRefs = nil

	var kept []*filer_pb.SubscribeMetadataResponse
	for _, e := range resp.Events {
		if eventInScope(e, prefixes) {
			kept = append(kept, e)
		}
	}
	resp.Events = kept

	if eventInScope(resp, prefixes) {
		return resp
	}
	if len(kept) == 0 {
		return nil
	}
	// The batch carries the position; keep it without the event it came with.
	return &filer_pb.SubscribeMetadataResponse{
		EventNotification: &filer_pb.EventNotification{},
		TsNs:              resp.TsNs,
		Events:            kept,
		FlushedTsNs:       resp.FlushedTsNs,
	}
}

func eventInScope(event *filer_pb.SubscribeMetadataResponse, prefixes []string) bool {
	n := event.GetEventNotification()
	if n == nil || (n.OldEntry == nil && n.NewEntry == nil) {
		return true // a position or heartbeat marker names no path
	}
	if n.OldEntry != nil && !security.MetadataPathInScope(filer_pb.MetadataEventSourceFullPath(event), prefixes) {
		return false
	}
	if n.NewEntry != nil && !security.MetadataPathInScope(filer_pb.MetadataEventTargetFullPath(event), prefixes) {
		return false
	}
	return true
}

type scopedSubscribeStream struct {
	filer_pb.SeaweedFiler_SubscribeMetadataServer
	prefixes []string
}

func (s *scopedSubscribeStream) Send(resp *filer_pb.SubscribeMetadataResponse) error {
	if scoped := scopeMetadataResponse(resp, s.prefixes); scoped != nil {
		return s.SeaweedFiler_SubscribeMetadataServer.Send(scoped)
	}
	return nil
}

type scopedSubscribeLocalStream struct {
	filer_pb.SeaweedFiler_SubscribeLocalMetadataServer
	prefixes []string
}

func (s *scopedSubscribeLocalStream) Send(resp *filer_pb.SubscribeMetadataResponse) error {
	if scoped := scopeMetadataResponse(resp, s.prefixes); scoped != nil {
		return s.SeaweedFiler_SubscribeLocalMetadataServer.Send(scoped)
	}
	return nil
}
