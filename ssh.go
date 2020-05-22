package main

import (
	"bufio"
	"fmt"
	"github.com/pkg/browser"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/terminal"
	"io"
	"net/url"
	"os"
	"regexp"
	"time"
)

// Open SSH connection with agent forwarding;
// Handle keyboardinteractive challenge/response.
func connectToServer(s Server, agent_path, redirectURI string, responseChan chan string) error {
	console := bufio.NewScanner(os.Stdin)
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
		//HostKeyCallback: ssh.FixedHostKey(host_key),
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // FIXME
		BannerCallback:  ssh.BannerDisplayStderr(),
		Timeout:         30 * time.Second,
	}

	client, err := ssh.Dial("tcp", s.Host, sshConfig)
	if err != nil {
		return fmt.Errorf("Dial error: %v", err)
	}

	err = agent.ForwardToRemote(client, agent_path)
	if err != nil {
		return fmt.Errorf("Unable to open local agent: %v", err)
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
	responseChan chan string) []string {
	if len(questions) != 1 {
		return nil
	}
	u, err := extractURL(instruction)
	if err != nil {
		return nil
	}
	query := u.Query()
	query.Set("redirect_uri", redirectURI)
	u.RawQuery = query.Encode()
	err = browser.OpenURL(u.String())
	if err != nil {
		fmt.Fprintln(os.Stderr, "Unable to open browser:", err)
		return nil
	}
	code := <-responseChan
	code = fmt.Sprintf("%s %s", code, redirectURI)
	return []string{code}
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
