package outbound

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	tlsC "github.com/metacubex/mihomo/component/tls"
)

type RealityOptions struct {
	PublicKey     string `proxy:"public-key"`
	ShortID       string `proxy:"short-id,omitempty"`
	ClientVersion string `proxy:"client-version,omitempty"`

	SupportX25519MLKEM768 bool `proxy:"support-x25519mlkem768,omitempty"`
}

func (o RealityOptions) Parse() (*tlsC.RealityConfig, error) {
	if o.PublicKey != "" {
		config := new(tlsC.RealityConfig)
		config.SupportX25519MLKEM768 = o.SupportX25519MLKEM768
		config.ClientVersion = [3]byte{1, 8, 2}
		if o.ClientVersion != "" {
			parts := strings.Split(o.ClientVersion, ".")
			if len(parts) != 3 {
				return nil, errors.New("invalid REALITY client version")
			}
			for i, part := range parts {
				v, err := strconv.ParseUint(part, 10, 8)
				if err != nil {
					return nil, errors.New("invalid REALITY client version")
				}
				config.ClientVersion[i] = byte(v)
			}
		}

		const x25519ScalarSize = 32
		publicKey, err := base64.RawURLEncoding.DecodeString(o.PublicKey)
		if err != nil || len(publicKey) != x25519ScalarSize {
			return nil, errors.New("invalid REALITY public key")
		}
		config.PublicKey, err = ecdh.X25519().NewPublicKey(publicKey)
		if err != nil {
			return nil, fmt.Errorf("fail to create REALITY public key: %w", err)
		}

		n := hex.DecodedLen(len(o.ShortID))
		if n > tlsC.RealityMaxShortIDLen {
			return nil, errors.New("invalid REALITY short id")
		}
		n, err = hex.Decode(config.ShortID[:], []byte(o.ShortID))
		if err != nil || n > tlsC.RealityMaxShortIDLen {
			return nil, errors.New("invalid REALITY short ID")
		}

		return config, nil
	}
	return nil, nil
}
