package wire

import (
	pb "github.com/seawise-io/seawise-client/tunnelwire/tunnelpb"
)

func check(ok bool, field string) error {
	if !ok {
		return fail(CodeBadValue, field)
	}
	return nil
}

func firstErr(errs ...error) error {
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}

// ValidateHelloBody checks a decoded HelloBody against its limits.
func ValidateHelloBody(b *pb.HelloBody) error {
	return firstErr(
		check(len(b.ServerId) == 16, "server_id"),
		check(ValidKeyID(b.KeyId), "key_id"),
		check(len(b.RunId) == 16, "run_id"),
		check(ValidCapabilities(b.Capabilities), "capabilities"),
		check(ValidAgentVersion(b.AgentVersion), "agent_version"),
		check(b.Transport == pb.Transport_TRANSPORT_TLS || b.Transport == pb.Transport_TRANSPORT_WEBSOCKET, "transport"),
		check(len(b.TimeNonce) == 16, "time_nonce"),
		check(b.RoutesHeld <= MaxRoutesHeld, "routes_held"),
		check(b.MaxStreams >= 1 && b.MaxStreams <= MaxStreamsLimit, "max_streams"),
	)
}

// ValidateHelloAckBody checks a decoded HelloAckBody against its limits.
func ValidateHelloAckBody(b *pb.HelloAckBody) error {
	return firstErr(
		check(len(b.SessionId) == 16, "session_id"),
		check(ValidEdgeID(b.EdgeId), "edge_id"),
		check(ValidCapabilities(b.Capabilities), "capabilities"),
		check(len(b.OfferedDigest) == 32, "offered_digest"),
		check(b.MaxStreams >= 1 && b.MaxStreams <= MaxStreamsLimit, "max_streams"),
		check(b.MaxControlBytes == MaxControlMessage, "max_control_bytes"),
		check(b.MaxSessionAgeS >= MinSessionAgeS && b.MaxSessionAgeS <= MaxSessionAgeS, "max_session_age_s"),
	)
}

func validateBody(m *pb.ControlMessage) error {
	switch b := m.Body.(type) {
	case *pb.ControlMessage_Hello:
		h := b.Hello
		return firstErr(
			check(len(h.Body) >= 1 && len(h.Body) <= MaxHelloBody, "hello.body"),
			check(len(h.Signature) == SignatureSize, "hello.signature"),
		)
	case *pb.ControlMessage_HelloAck:
		h := b.HelloAck
		return firstErr(
			check(len(h.Body) >= 1 && len(h.Body) <= MaxHelloAckBody, "hello_ack.body"),
			check(len(h.Signature) == SignatureSize, "hello_ack.signature"),
		)
	case *pb.ControlMessage_HelloRefuse:
		r := b.HelloRefuse
		return firstErr(
			check(r.Code != pb.RefuseCode_REFUSE_UNSPECIFIED, "hello_refuse.code"),
			check(r.RetryAfterMs <= MaxRefuseRetryMs, "hello_refuse.retry_after_ms"),
			check(r.Code != pb.RefuseCode_OVERLOADED || r.RetryAfterMs > 0, "hello_refuse.retry_after_ms"),
			check(validDetail(r.Detail), "hello_refuse.detail"),
		)
	case *pb.ControlMessage_RouteSet:
		r := b.RouteSet
		return firstErr(
			check(ValidCompactJWS(r.Jws, MaxRouteSetJWS), "route_set.jws"),
			check(r.SignedTime == "" || ValidCompactJWS(r.SignedTime, MaxSignedTime), "route_set.signed_time"),
		)
	case *pb.ControlMessage_RouteSetAck:
		return check(b.RouteSetAck.Version >= 1, "route_set_ack.version")
	case *pb.ControlMessage_Ping, *pb.ControlMessage_Pong:
		return nil
	case *pb.ControlMessage_Drain:
		d := b.Drain
		return firstErr(
			check(d.Reason != pb.DrainReason_DRAIN_UNSPECIFIED, "drain.reason"),
			check(d.DeadlineMs >= MinDrainMs && d.DeadlineMs <= MaxDrainMs, "drain.deadline_ms"),
			check(d.Action != pb.DrainAction_STOP || d.Reason == pb.DrainReason_SUPERSEDED, "drain.action"),
		)
	case *pb.ControlMessage_Revoke:
		r := b.Revoke
		app := r.Scope == pb.RevokeScope_APP
		return firstErr(
			check(r.Scope != pb.RevokeScope_REVOKE_UNSPECIFIED, "revoke.scope"),
			check(app && len(r.AppId) == 16 || !app && len(r.AppId) == 0, "revoke.app_id"),
			check(validDetail(r.Detail), "revoke.detail"),
		)
	case *pb.ControlMessage_MinVersion:
		v := b.MinVersion
		return firstErr(
			check(ValidAgentVersion(v.MinAgentVersion), "min_version.min_agent_version"),
			check(v.EffectiveAt > 0, "min_version.effective_at"),
		)
	case *pb.ControlMessage_PolicyVersion:
		p := b.PolicyVersion
		return firstErr(
			check(p.Version >= 1, "policy_version.version"),
			check(p.Flags == "" || ValidCompactJWS(p.Flags, MaxFlags), "policy_version.flags"),
		)
	case *pb.ControlMessage_DeviceCall:
		c := b.DeviceCall
		_, _, twinErr := TwinPath(c.Method, c.PathSuffix)
		return firstErr(
			check(c.CallId >= 1 && c.CallId <= MaxCallID, "device_call.call_id"),
			check(len(c.IdempotencyKey) == 16, "device_call.idempotency_key"),
			check(c.Method != pb.DeviceMethod_METHOD_UNSPECIFIED, "device_call.method"),
			check(twinErr == nil, "device_call.path_suffix"),
			check(ValidCompactJWS(c.Dpop, MaxDPoP), "device_call.dpop"),
		)
	case *pb.ControlMessage_DeviceResult:
		r := b.DeviceResult
		done := r.Class == pb.ResultClass_DONE
		return firstErr(
			check(r.CallId >= 1 && r.CallId <= MaxCallID, "device_result.call_id"),
			check(r.Class != pb.ResultClass_CLASS_UNSPECIFIED, "device_result.class"),
			check(done && r.HttpStatus >= 100 && r.HttpStatus <= 599 || !done && r.HttpStatus == 0, "device_result.http_status"),
			check(validNonce(r.DpopNonce), "device_result.dpop_nonce"),
			check(r.RetryAfterMs <= MaxResultRetryMs, "device_result.retry_after_ms"),
		)
	case *pb.ControlMessage_Error:
		e := b.Error
		return firstErr(
			check(e.Code != pb.ErrorCode_ERROR_UNSPECIFIED, "error.code"),
			check(validDetail(e.Detail), "error.detail"),
		)
	}
	return fail(CodeNoBody, "body")
}
