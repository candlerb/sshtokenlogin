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
func runServer(listenAddresses []string, redirectURIHostname string, responseChan chan Response) (string, error) {
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
			return fmt.Sprintf("http://%s:%d/callback", redirectURIHostname, listenPort), nil
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
		die("Loading settings: %v", err)
	}

	// Open agent connection
	agent_path := os.Getenv("SSH_AUTH_SOCK")
	if agent_path == "" {
		die("SSH_AUTH_SOCK not set.  This program requires access to an ssh agent")
	}
	agent_conn, err := NewRestrictedAgent(agent_path)
	if err != nil {
		die("Connecting to local agent: %v", err)
	}

	// Prepare HTTP server for receiving OIDC response code
	responseChan := make(chan Response)
	redirectURI, err := runServer(settings.ListenAddresses, settings.RedirectURIHostname, responseChan)
	if err != nil {
		die("Failed to start http: %v", err)
	}

	for _, server := range servers {
		conf := settings.Servers[server]
		if conf == nil {
			die("Server '%s' not present in config", server)
		}
		err = connectToServer(conf, agent_conn, redirectURI, responseChan)
		if err != nil {
			die("Server '%s': %v", server, err)
		}
	}
}

// TODO: debug logging at each stage
