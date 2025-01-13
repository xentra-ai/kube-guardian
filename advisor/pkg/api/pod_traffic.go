package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	log "github.com/rs/zerolog/log"

	v1 "k8s.io/api/core/v1"
)

type PodTraffic struct {
	UUID         string      `yaml:"uuid" json:"uuid"`
	SrcPodName   string      `yaml:"pod_name" json:"pod_name"`
	SrcIP        string      `yaml:"pod_ip" json:"pod_ip"`
	SrcNamespace string      `yaml:"pod_namespace" json:"pod_namespace"`
	SrcPodPort   string      `yaml:"pod_port" json:"pod_port"`
	TrafficType  string      `yaml:"traffic_type" json:"traffic_type"`
	DstIP        string      `yaml:"traffic_in_out_ip" json:"traffic_in_out_ip"`
	DstPort      string      `yaml:"traffic_in_out_port" json:"traffic_in_out_port"`
	Protocol     v1.Protocol `yaml:"ip_protocol" json:"ip_protocol"`
}

type PodDetail struct {
	UUID      string `yaml:"uuid" json:"uuid"`
	PodIP     string `yaml:"pod_ip" json:"pod_ip"`
	Name      string `yaml:"pod_name" json:"pod_name"`
	Namespace string `yaml:"pod_namespace" json:"pod_namespace"`
	Pod       v1.Pod `yaml:"pod_obj" json:"pod_obj"`
}

type SvcDetail struct {
	SvcIp        string     `yaml:"svc_ip" json:"svc_ip"`
	SvcName      string     `yaml:"svc_name" json:"svc_name"`
	SvcNamespace string     `yaml:"svc_namespace" json:"svc_namespace"`
	Service      v1.Service `yaml:"service_spec" json:"service_spec"`
}

func GetPodTraffic(podName string) ([]PodTraffic, error) {

	time.Sleep(3 * time.Second)
	// Specify the URL of the REST API endpoint you want to invoke.
	apiURL := "http://127.0.0.1:9090/pod/traffic" + podName

	// Send an HTTP GET request to the API endpoint.
	resp, err := http.Get(apiURL)
	if err != nil {
		log.Error().Err(err).Msg("GetPodTraffic: Error making GET request")
		return nil, err
	}
	defer resp.Body.Close()
	// Check the HTTP status code.
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GetPodTraffic: received non-OK HTTP status code: %v", resp.StatusCode)
	}
	var podTraffic []PodTraffic

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Error().Err(err).Msg("GetPodTraffic: Error reading response body")
		return nil, err
	}

	// Parse the JSON response and unmarshal it into the Go struct.
	if err := json.Unmarshal([]byte(body), &podTraffic); err != nil {
		log.Error().Err(err).Msg("GetPodTraffic: Error unmarshal JSON")
		return nil, err
	}

	// If no pod traffic is found, return err
	if len(podTraffic) == 0 {
		return nil, fmt.Errorf("GetPodTraffic: No pod traffic found in database")
	}

	return podTraffic, nil
}

// Should we just get the pod spec directly from the cluster and only use the DB for the SaaS version where it contains the pod spec? Would this help with reducing unnecessary chatter?And just let the client do it?
func GetPodSpec(ip string) (*PodDetail, error) {

	// Specify the URL of the REST API endpoint you want to invoke.
	apiURL := "http://127.0.0.1:9090/pod/ip/" + ip

	// Send an HTTP GET request to the API endpoint.
	resp, err := http.Get(apiURL)
	if err != nil {
		log.Error().Err(err).Msg("Error making GET request")
		return nil, err
	}
	defer resp.Body.Close()

	// Check the HTTP status code.
	if resp.StatusCode != http.StatusOK {
		log.Debug().Msgf("received non-OK HTTP status code: %v", resp.StatusCode)
		return nil, nil
	}

	var details *PodDetail

	// Parse the JSON response and unmarshal it into the Go struct.
	if err := json.NewDecoder(resp.Body).Decode(&details); err != nil {
		log.Error().Err(err).Msg("Error decoding JSON")
		return nil, err
	}

	// If no pod details are found, return err
	if details == nil {
		return nil, fmt.Errorf("no pod details found in database")
	}

	return details, nil
}

func GetSvcSpec(svcIp string) (*SvcDetail, error) {

	// Specify the URL of the RESTAPI endpoint you want to invoke.
	apiURL := "http://127.0.0.1:9090/svc/ip/" + svcIp

	// Send an HTTP GET request to the API endpoint.
	resp, err := http.Get(apiURL)
	if err != nil {
		log.Error().Err(err).Msg("Error making GET request")
		return nil, err
	}
	defer resp.Body.Close()

	// Check the HTTP status code.
	if resp.StatusCode != http.StatusOK {
		log.Debug().Msgf("received non-OK HTTP status code: %v", resp.StatusCode)
		return nil, nil
	}

	var details SvcDetail

	// Parse the JSON response and unmarshal it into the Go struct.
	if err := json.NewDecoder(resp.Body).Decode(&details); err != nil {
		log.Error().Err(err).Msg("Error decoding JSON")
		return nil, err
	}

	return &details, nil
}
