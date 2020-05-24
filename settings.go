package main

import (
	"bytes"
	"fmt"
	"golang.org/x/crypto/ssh"
	yaml "gopkg.in/yaml.v3"
	"os"
)

type Settings struct {
	ListenAddresses []string           `yaml:"listen_addresses"`
	Servers         map[string]*Server `yaml:"servers"`
}

type Server struct {
	Host     string
	User     string
	HostKeys string `yaml:"host_keys"`
	CAKeys   string `yaml:"ca_keys"`

	trustedHostKeys []ssh.PublicKey
	trustedCAKeys   []ssh.PublicKey
}

// Load a settings yaml file into a Settings struct
func SettingsLoad(yamlFilePath string) (Settings, error) {
	file, err := os.Open(yamlFilePath)
	if err != nil {
		return Settings{}, err
	}
	defer file.Close()

	settings := Settings{}
	dec := yaml.NewDecoder(file)
	dec.KnownFields(true)
	err = dec.Decode(&settings)
	if err != nil {
		return settings, err
	}

	if len(settings.ListenAddresses) == 0 {
		settings.ListenAddresses = defaultListenAddresses
	}

	// Check entries
	for name, server := range settings.Servers {
		if server.Host == "" {
			return settings, fmt.Errorf("Server %s: missing host", name)
		}
		if server.User == "" {
			return settings, fmt.Errorf("Server %s: missing user", name)
		}
		settings.Servers[name].trustedHostKeys, err = LoadAuthorizedKeysBytes([]byte(server.HostKeys))
		if err != nil {
			return settings, fmt.Errorf("Server %s: host_keys: %v", name, err)
		}
		server.trustedCAKeys, err = LoadAuthorizedKeysBytes([]byte(server.CAKeys))
		if err != nil {
			return settings, fmt.Errorf("Server %s: ca_keys: %v", name, err)
		}
		if len(server.trustedHostKeys) == 0 && len(server.trustedCAKeys) == 0 {
			return settings, fmt.Errorf("Server %s: must provide host_keys or ca_keys", name)
		}
	}

	return settings, nil
}

// Parse authorized_keys from []byte
func LoadAuthorizedKeysBytes(authorizedKeysBytes []byte) ([]ssh.PublicKey, error) {
	var akeys []ssh.PublicKey

	for len(authorizedKeysBytes) > 0 {
		pubKey, _, _, rest, err := ssh.ParseAuthorizedKey(authorizedKeysBytes)
		if err != nil {
			i := bytes.IndexAny(authorizedKeysBytes, "\n")
			if i > 1 {
				authorizedKeysBytes = authorizedKeysBytes[0 : i-1]
			}
			return akeys, fmt.Errorf("Error parsing public key \"%s\": %v", authorizedKeysBytes, err)
		}
		akeys = append(akeys, pubKey)
		authorizedKeysBytes = rest
	}
	return akeys, nil
}
