package config

import (
	"github.com/kelseyhightower/envconfig"
)

// APIConfig API InternalConfig
// - InternalConfigSource specifies the source for internal configs - file or datastore
// nolint: lll
type APIConfig struct {
	AppName    string `envconfig:"APP_NAME" default:"go-papyrus"`
	AppEnv     string `envconfig:"ENVIRONMENT" required:"true"`
	Port       int    `envconfig:"API_PORT" default:"80"`
	Version    string `envconfig:"VERSION"`
	LogChannel string `envconfig:"LOG_CHANNEL" default:"go-papyrus-api"`
	LogLevel   string `envconfig:"LOG_LEVEL" default:"error"`
}

// LoadConfigFromEnv Loads configuration from OS.Env
func (ac *APIConfig) LoadConfigFromEnv() error {
	return envconfig.Process("", ac)
}

// New bare API config struct
func New() *APIConfig {
	return &APIConfig{}
}
