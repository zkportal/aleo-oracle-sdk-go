package aleo_oracle_sdk

import (
	"errors"
	"net"
)

func resolveIPv4(hostname string) ([]string, error) {
	ips, err := net.LookupIP(hostname)
	if err != nil {
		return nil, err
	}

	v4s := make([]string, 0)
	// collect IPv4 address
	for _, ip := range ips {
		if ip.To4() != nil {
			v4s = append(v4s, ip.String())
		}
	}

	if len(v4s) == 0 {
		return nil, errors.New("hostname lookup found no IPv4 addresses")
	}

	return v4s, nil
}
