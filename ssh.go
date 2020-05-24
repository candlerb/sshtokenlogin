package main

import (
	"bufio"
	"bytes"
	"fmt"
	"github.com/pkg/browser"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/terminal"
	"io"
	"math/rand"
	"net"
	"net/url"
	"os"
	"regexp"
	"time"
)

type Response struct {
	Code  string
	State string
}

// Open SSH connection with agent forwarding;
// Handle keyboardinteractive challenge/response.
func connectToServer(s *Server, agent_conn agent.ExtendedAgent, redirectURI string, responseChan chan Response) error {
	console := bufio.NewScanner(os.Stdin)

	certChecker := ssh.CertChecker{
		IsHostAuthority: func(key ssh.PublicKey, address string) bool {
			for _, cakey := range s.trustedCAKeys {
				if bytes.Equal(key.Marshal(), cakey.Marshal()) {
					return true
				}
			}
			return false
		},
		HostKeyFallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			for _, hostkey := range s.trustedHostKeys {
				if bytes.Equal(key.Marshal(), hostkey.Marshal()) {
					return nil
				}
			}
			return fmt.Errorf("host public key not matched")
		},
	}
	sshConfig := &ssh.ClientConfig{
		User: s.User,
		Auth: []ssh.AuthMethod{
			ssh.KeyboardInteractive(func(user, instruction string, questions []string, echos []bool) ([]string, error) {
				answers := browserChallenge(instruction, questions, redirectURI, responseChan)
				if answers != nil {
					return answers, nil
				}
				return keyboardChallenge(instruction, questions, echos, console)
			}),
		},
		HostKeyCallback: certChecker.CheckHostKey,
		BannerCallback:  ssh.BannerDisplayStderr(),
		Timeout:         30 * time.Second,
	}

	client, err := ssh.Dial("tcp", s.Host, sshConfig)
	if err != nil {
		return fmt.Errorf("Dial error: %v", err)
	}

	err = agent.ForwardToAgent(client, agent_conn)
	if err != nil {
		return fmt.Errorf("Unable to forward to agent: %v", err)
	}
	session, err := client.NewSession()
	if err != nil {
		client.Close()
		return fmt.Errorf("Unable to open session: %v", err)
	}

	// Consume any messages
	stdout, err := session.StdoutPipe()
	if err != nil {
		fmt.Println("Unable to connect stdout:", err)
	} else {
		go io.Copy(os.Stdout, stdout)
	}
	stderr, err := session.StderrPipe()
	if err != nil {
		fmt.Println("Unable to connect stderr:", err)
	} else {
		go io.Copy(os.Stderr, stderr)
	}

	// Request agent forwarding - currently required
	// to trigger certificate issuance
	err = agent.RequestAgentForwarding(session)
	if err != nil {
		return fmt.Errorf("Unable to request agent forwarding: %v", err)
	}

	// Wait for server to close
	err = client.Conn.Wait()
	if err != nil && err != io.EOF {
		return fmt.Errorf("Error waiting for close: %v", err)
	}

	return nil
}

// Try to handle challenge/response via web
func browserChallenge(instruction string, questions []string, redirectURI string,
	responseChan chan Response) []string {
	if len(questions) != 1 {
		return nil
	}
	u, err := extractURL(instruction)
	if err != nil {
		return nil
	}
	query := u.Query()
	if query.Get("client_id") == "" || query.Get("response_type") != "code" {
		// Not a usable OpenID Connect URL
		return nil
	}
	state := query.Get("state")
	if state == "" {
		state = fmt.Sprintf("%016X", rand.Uint64())
		query.Set("state", state)
	}
	query.Set("redirect_uri", redirectURI)
	u.RawQuery = query.Encode()
	err = browser.OpenURL(u.String())
	if err != nil {
		fmt.Fprintln(os.Stderr, "Unable to open browser:", err)
		return nil
	}
	for response := range responseChan {
		if response.Code == "" {
			fmt.Fprintln(os.Stderr, "Callback: Missing code")
			continue
		}
		if response.State != state {
			fmt.Fprintln(os.Stderr, "Callback: Unexpected state")
			continue
		}
		return []string{fmt.Sprintf("%s %s", response.Code, redirectURI)}
	}
	return nil
}

// Extract the IDP auth URL out of the prompt
func extractURL(instruction string) (*url.URL, error) {
	url_re := regexp.MustCompile(`https?://.+`)
	raw := url_re.FindString(instruction)
	if raw == "" {
		return nil, fmt.Errorf("Instruction did not contain URL")
	}
	u, err := url.ParseRequestURI(raw)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("Invalid URL scheme")
	}
	return u, nil
}

// Fallback: use keyboard challenge/response
// (e.g. on systems where browser is not available)
func keyboardChallenge(instruction string, questions []string, echos []bool,
	console *bufio.Scanner) ([]string, error) {
	fmt.Println(instruction)
	answers := make([]string, len(questions))
	for i, q := range questions {
		var line []byte
		var err error
		fmt.Print(q)
		if echos[i] {
			if !console.Scan() {
				err = fmt.Errorf("Input scan terminated")
			} else {
				line = console.Bytes()
				err = console.Err()
			}

		} else {
			line, err = terminal.ReadPassword(0)
			answers[i] = string(line)
			fmt.Println("")
		}
		if err != nil {
			return nil, err
		}
		answers[i] = string(line)
	}
	return answers, nil
}
