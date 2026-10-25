package wire

// Limits of seawise-tunnel/1.
const (
	MaxControlMessage = 65536 // bytes of one ControlMessage on stream 0
	MaxHelloBody      = 4096
	MaxHelloAckBody   = 2048
	SignatureSize     = 64
	MaxHeader         = 4096 // StreamHeader
	MaxReply          = 64   // StreamReply
	MaxRelayPrefix    = 128  // RelayPrefix
	MaxRouteSetJWS    = 61440
	MaxSignedTime     = 1024
	MaxFlags          = 16384
	MaxDeviceBody     = 57344
	MaxDPoP           = 2048
	MaxPathSuffix     = 256
	MaxDPoPNonce      = 256
	MaxVisitorToken   = 2048
	MaxStaleOk        = 512
	MaxDetail         = 128
	MaxCapabilities   = 32
	MaxCapabilityLen  = 32
	MaxAgentVersion   = 32
	MaxEdgeID         = 63
	MaxRoutesHeld     = 1000
	MaxStreamsLimit   = 4096
	MaxCallID         = 1<<31 - 1
	MaxRefuseRetryMs  = 86400000
	MaxResultRetryMs  = 300000
	MinDrainMs        = 1000
	MaxDrainMs        = 120000
	MinSessionAgeS    = 43200
	MaxSessionAgeS    = 86400
	SchemaVersion     = 1
	HeaderVersion     = 1
	RelayVersion      = 1
	RelayHop          = 1
)

// ALPN protocol IDs and the WebSocket fallback.
const (
	ALPN              = "sw-tunnel/1"
	ALPNWebSocket     = "http/1.1"
	WebSocketPath     = "/__seawise/tunnel"
	WebSocketProtocol = "sw-tunnel.1"
	MaxWebSocketMsg   = 1 << 20
)

// First and last field numbers of ControlMessage reserved for capabilities.
const (
	firstCapabilityField = 24
	lastCapabilityField  = 99
)
