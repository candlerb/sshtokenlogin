package main

import (
	"fmt"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"net"
)

// Minimise the number of requests we forward to the underlying agent
type RestrictedAgent struct {
	conn       net.Conn
	agent_conn agent.ExtendedAgent
}

var (
	ErrForbidden = fmt.Errorf("Request forbidden")
)

func NewRestrictedAgent(agent_path string) (*RestrictedAgent, error) {
	if agent_path == "" {
		return nil, fmt.Errorf("agent path not set")
	}
	conn, err := net.Dial("unix", agent_path)
	if err != nil {
		return nil, err
	}
	return &RestrictedAgent{
		conn:       conn,
		agent_conn: agent.NewClient(conn),
	}, nil
}

func (ra *RestrictedAgent) Close() error {
	return ra.conn.Close()
}

// Allow adding a private key+cert to the agent
func (ra *RestrictedAgent) Add(key agent.AddedKey) error {
	return ra.agent_conn.Add(key)
}

// Allow listing of keys/certs
func (ra *RestrictedAgent) List() ([]*agent.Key, error) {
	return ra.agent_conn.List()
}

// All other operations are forbidden - especially signing
func (ra *RestrictedAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return nil, ErrForbidden
}

func (ra *RestrictedAgent) Remove(key ssh.PublicKey) error {
	return ErrForbidden
}

func (ra *RestrictedAgent) RemoveAll() error {
	return ErrForbidden
}

func (ra *RestrictedAgent) Lock(passphrase []byte) error {
	return ErrForbidden
}

func (ra *RestrictedAgent) Unlock(passphrase []byte) error {
	return ErrForbidden
}

func (ra *RestrictedAgent) Signers() ([]ssh.Signer, error) {
	return nil, ErrForbidden
}

func (ra *RestrictedAgent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	return nil, ErrForbidden
}

func (ra *RestrictedAgent) Extension(extensionType string, contents []byte) ([]byte, error) {
	return nil, agent.ErrExtensionUnsupported
}
