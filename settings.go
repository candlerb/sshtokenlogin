package main

import (
	yaml "gopkg.in/yaml.v3"
	"os"
)

type Settings struct {
	ListenAddresses []string          `yaml:"listen_addresses"`
	Servers         map[string]Server `yaml:"servers"`
}

type Server struct {
	Host string
	User string
}

// Load a settings yaml file into a Settings struct
func SettingsLoad(yamlFilePath string) (Settings, error) {
	file, err := os.Open(yamlFilePath)
	if err != nil {
		return Settings{}, err
	}
	defer file.Close()

	s := Settings{}
	dec := yaml.NewDecoder(file)
	dec.KnownFields(true)
	err = dec.Decode(&s)
	if err != nil {
		return s, err
	}
	return s, nil
}
