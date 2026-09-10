package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	log "github.com/rs/zerolog/log"
)

// ComputeFindingVictim identifies the container a compute finding is about.
// Mirrors the broker's Finding.victim (docs/design/compute-contention-monitoring.md, D7).
type ComputeFindingVictim struct {
	PodUID       string `json:"pod_uid"`
	Namespace    string `json:"namespace"`
	PodName      string `json:"pod_name"`
	Container    string `json:"container"`
	ContainerUID string `json:"container_uid"`
	Node         string `json:"node"`
}

// ComputeFindingCulprit is the cgroup the broker blames for a finding. nil
// on the self-inflicted kinds (cpu-throttled, memory-limit-thrash). Kind is
// "pod", "system" or "kernel"; the pod_* fields are only set for Kind=="pod".
// BlameShare, CPUUsageMillis and CPURequestMillis are pointers because the
// broker sends null when it does not know — CPUUsageMillis in particular is
// null for a culprit pod that opted out of sampling (kguardian.dev/compute=off)
// — and nil must render as "-", never as 0.
type ComputeFindingCulprit struct {
	Kind             string   `json:"kind"`
	Ref              string   `json:"ref"`
	PodUID           *string  `json:"pod_uid"`
	Namespace        *string  `json:"namespace"`
	PodName          *string  `json:"pod_name"`
	ContainerUID     *string  `json:"container_uid"`
	BlameShare       *float64 `json:"blame_share"`
	CPUUsageMillis   *float64 `json:"cpu_usage_millis"`
	CPURequestMillis *int64   `json:"cpu_request_millis"`
}

// ComputeFinding is one row of GET /compute/findings. Evidence is kept raw:
// the table output never reads it and the JSON output must pass it through
// unchanged, so decoding it into a struct would only invite drift.
type ComputeFinding struct {
	Kind      string                 `json:"kind"`
	Severity  string                 `json:"severity"`
	Victim    ComputeFindingVictim   `json:"victim"`
	Culprit   *ComputeFindingCulprit `json:"culprit"`
	Evidence  json.RawMessage        `json:"evidence,omitempty"`
	FirstSeen string                 `json:"first_seen"`
	LastSeen  string                 `json:"last_seen"`
	Message   string                 `json:"message"`
}

// ComputeFindingsResponse is the envelope of GET /compute/findings.
type ComputeFindingsResponse struct {
	Findings []ComputeFinding `json:"findings"`
}

// GetComputeFindingsFunc is swappable for tests that bypass HTTP entirely.
var GetComputeFindingsFunc = getRealComputeFindings

// GetComputeFindings fetches the broker's compute findings. namespace and
// node are optional filters (empty = not sent); with neither the broker
// returns the whole cluster. It returns the decoded findings AND the raw
// response body so `-o json` can emit exactly what the broker said, fields
// this CLI build does not know about included.
func GetComputeFindings(namespace, node string) (*ComputeFindingsResponse, []byte, error) {
	return GetComputeFindingsFunc(namespace, node)
}

func getRealComputeFindings(namespace, node string) (*ComputeFindingsResponse, []byte, error) {
	q := url.Values{}
	if namespace != "" {
		q.Set("namespace", namespace)
	}
	if node != "" {
		q.Set("node", node)
	}
	path := "/compute/findings"
	if enc := q.Encode(); enc != "" {
		path += "?" + enc
	}

	resp, err := brokerGet(path)
	if err != nil {
		log.Error().Err(err).Msg("GetComputeFindings: Error making GET request")
		return nil, nil, err
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Error().Err(closeErr).Msg("GetComputeFindings: Error closing response body")
		}
	}()
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("GetComputeFindings: received non-OK HTTP status code: %v", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBrokerResponseBytes))
	if err != nil {
		log.Error().Err(err).Msg("GetComputeFindings: Error reading response body")
		return nil, nil, err
	}
	var out ComputeFindingsResponse
	if err := json.Unmarshal(body, &out); err != nil {
		log.Error().Err(err).Msg("GetComputeFindings: Error unmarshalling JSON")
		return nil, nil, err
	}
	return &out, body, nil
}
