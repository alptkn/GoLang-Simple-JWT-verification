package configs

import "github.com/spf13/viper"

type envConfigs struct {
	LocalServerPort string `mapstructure:"LOCAL_SERVER_PORT"`
	SecretKey       string `mapstrcuture:"SECRET_KEY"`
}

var Configs *envConfigs

func LoadConfigs() {
	Configs = loadEnvVariables()
}

func loadEnvVariables() (Configs *envConfigs) {
	viper.AddConfigPath(".")
	viper.SetConfigName("app")
	viper.SetConfigType("env")
	if err := viper.ReadInConfig(); err != nil {
		panic(err)
	}

	if err := viper.Unmarshal(&Configs); err != nil {
		panic(err)
	}
	return
}
