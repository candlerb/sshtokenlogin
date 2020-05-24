package main

import (
	"flag"
	"fmt"
	homedir "github.com/mitchellh/go-homedir"
	"net"
	"net/http"
	"os"
)

const (
	// TODO: OS-specific location for Windows etc.
	defaultConfigFile = "~/.config/sshtokenlogin/sshtokenlogin.yaml"
)

var (
	defaultListenAddresses = []string{"1.2.3.4:80", "[::1]:0"}
)

// Run server on first available listen address, return the redirectURI
func runServer(listenAddresses []string, responseChan chan Response) (string, error) {
	http.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		response := Response{
			Code:  r.URL.Query().Get("code"),
			State: r.URL.Query().Get("state"),
		}
		if response.Code == "" {
			http.Error(w, "<p>Missing response code</p>", http.StatusBadRequest)
		} else {
			// Note: modern browsers don't allow Javascript to close the window/tab
			fmt.Fprintf(w, "<p>Code accepted</p>")
		}
		responseChan <- response
	})
	for _, addr := range listenAddresses {
		listener, err := net.Listen("tcp", addr)
		if err == nil {
			go func() {
				panic(http.Serve(listener, nil))
			}()
			listenPort := listener.Addr().(*net.TCPAddr).Port
			return fmt.Sprintf("http://localhost:%d/callback", listenPort), nil
		}
	}
	return "", fmt.Errorf("Unable to bind to any listenAddress")
}

func die(format string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", a...)
	os.Exit(1)
}

func main() {
	var err error

	// Parse args
	config := os.Getenv("SSHTOKENLOGIN_CONFIG")
	if config == "" {
		config, err = homedir.Expand(defaultConfigFile)
		if err != nil {
			die("%v", err)
		}
	}
	flag.StringVar(&config, "config", config,
		"Location of YAML config file")
	flag.Parse()

	servers := flag.Args()
	if len(servers) == 0 {
		servers = []string{"default"}
	}

	// Read config
	settings, err := SettingsLoad(config)
	if err != nil {
		die("%v", err)
	}

	// Locate local agent socket
	agent_path := os.Getenv("SSH_AUTH_SOCK")
	if agent_path == "" {
		die("SSH_AUTH_SOCK not set.  This program requires access to an ssh agent")
	}

	// Prepare HTTP server for receiving OIDC response code
	responseChan := make(chan Response)
	redirectURI, err := runServer(settings.ListenAddresses, responseChan)
	if err != nil {
		die("Failed to start http: %v", err)
	}

	for _, server := range servers {
		conf := settings.Servers[server]
		if conf == nil {
			die("Server '%s' not present in config", server)
		}
		err = connectToServer(conf, agent_path, redirectURI, responseChan)
		if err != nil {
			die("Server '%s': %v", server, err)
		}
	}
}

// TODO: debug logging at each stage
