package k8s

import (
	log "github.com/rs/zerolog/log"
	corev1 "k8s.io/api/core/v1"
)

// Version is set at build time using -ldflags
var Version = "development" // default value

// ModeType defines the mode of operation for generating network policies
type ModeType int

const (
	SinglePod ModeType = iota
	AllPodsInNamespace
	AllPodsInAllNamespaces
)

// GenerateOptions holds options for the GenerateNetworkPolicy function
type GenerateOptions struct {
	Mode      ModeType
	PodName   string // Used if Mode is SinglePod
	Namespace string // Used if Mode is AllPodsInNamespace or SinglePod
}

func GetResource(options GenerateOptions, config *Config) []corev1.Pod {
	var pods []corev1.Pod

	switch options.Mode {
	case SinglePod:
		// Fetch all pods in the given namespace
		fetchedPod, err := fetchSinglePodInNamespace(options.PodName, options.Namespace, config)
		if err != nil {
			log.Fatal().Err(err).Msgf("failed to fetch pods in namespace %s", options.Namespace)
		}
		pods = append(pods, *fetchedPod)

	case AllPodsInNamespace:
		// Fetch all pods in the given namespace
		fetchedPods, err := fetchAllPodsInNamespace(options.Namespace, config)
		if err != nil {
			log.Fatal().Err(err).Msgf("failed to fetch pods in namespace %s", options.Namespace)
		}
		pods = append(pods, fetchedPods...)

	case AllPodsInAllNamespaces:
		// Fetch all pods in all namespaces
		fetchedPods, err := fetchAllPodsInAllNamespaces(config)
		if err != nil {
			log.Fatal().Err(err).Msgf("failed to fetch all pods in all namespaces")
		}
		pods = append(pods, fetchedPods...)
	}
	return pods
}
