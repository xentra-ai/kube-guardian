package cmd

import (
	"os"

	"github.com/rs/zerolog"
	log "github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/xentra-ai/advisor/pkg/k8s"
)

var cfg = &k8s.Broker{
	ServiceNamespace: "kube-guardian",
	ServiceName:      "broker",
	Ports:            []string{"9090:9090"},
}

var debug bool

func init() {
	// Set up logging to console
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	zerolog.SetGlobalLevel(zerolog.InfoLevel)

	// Add your sub-commands
	genCmd.AddCommand(networkPolicyCmd, seccompCmd)

	// Add flags
	genCmd.PersistentFlags().String("kubeconfig", "", "Path to the kubeconfig file to use for CLI requests.")
	genCmd.PersistentFlags().String("namespace", "", "If present, the namespace scope for this CLI request")

	// Adding flags for service namespace, service name, and ports
	genCmd.PersistentFlags().StringVar(&cfg.ServiceNamespace, "service-namespace", cfg.ServiceNamespace, "If present, the namespace of the broker service")
	genCmd.PersistentFlags().StringVar(&cfg.ServiceName, "service-name", cfg.ServiceName, "If present, the name of the broker service")
	genCmd.PersistentFlags().StringSliceVar(&cfg.Ports, "ports", cfg.Ports, "If present, the list of broker ports to forward")

	// Add debug flag to rootCmd so it's available for all sub-commands
	rootCmd.PersistentFlags().BoolVar(&debug, "debug", false, "sets log level to debug")

	rootCmd.AddCommand(genCmd)

	// Set up colored output
	consoleWriter := zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: zerolog.TimeFieldFormat, NoColor: false}
	log.Logger = log.Output(consoleWriter)
}

var rootCmd = &cobra.Command{
	Use:   "xentra",
	Short: "Xentra is a security tool for enhancing Kubernetes application profiles",
	Long: `Xentra is designed to improve the security profile of applications running in
	       Kubernetes clusters. It provides various functionalities like generating network
	       policies, seccomp profiles, and more to ensure that your applications meet
	       best security practices.
	       Complete documentation is available at [Your Documentation URL]`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// Adjust log level according to the flag
		if debug {
			zerolog.SetGlobalLevel(zerolog.DebugLevel)
		}
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		log.Fatal().Err(err).Msg("Error executing command")
	}
}
