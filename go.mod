module github.com/seawise/client

go 1.26.9

require (
	github.com/sigstore/sigstore v1.10.6
	github.com/spf13/cobra v1.10.2
	github.com/theupdateframework/go-tuf/v2 v2.4.2
	golang.org/x/crypto v0.57.0
)

require (
	github.com/cenkalti/backoff/v5 v5.0.3 // indirect
	github.com/google/go-containerregistry v0.20.7 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/libp2p/go-buffer-pool v0.0.2 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/secure-systems-lab/go-securesystemslib v0.11.0 // indirect
	github.com/sigstore/protobuf-specs v0.5.0 // indirect
	github.com/spf13/pflag v1.0.9 // indirect
	golang.org/x/term v0.46.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20250825161204-c5933d9347a5 // indirect
)

require (
	github.com/libp2p/go-yamux/v5 v5.1.0
	github.com/seawise-io/seawise-client/tunnelwire v0.0.0
	golang.org/x/sys v0.48.0
	google.golang.org/protobuf v1.36.11
)

replace github.com/seawise-io/seawise-client/tunnelwire => ./tunnelwire
