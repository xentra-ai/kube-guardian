package main

import (
	"log"
	"time"

	"github.com/xUnholy/advisor-controller/db"
	"github.com/xUnholy/advisor-controller/k8s"
)

func main() {
	today := time.Now().Format("2006-01-02")

	dbClient, err := db.New("user=pqgotest dbname=pqgotest sslmode=verify-full")
	if err != nil {
		log.Fatalf("Failed to create database client: %v", err)
	}

	k8sClient, err := k8s.New("")
	if err != nil {
		log.Fatalf("Failed to create Kubernetes client: %v", err)
	}

	policies, err := dbClient.GetPolicies(today)
	if err != nil {
		log.Fatalf("Failed to get policies: %v", err)
	}

	for _, policy := range policies {
		if err := k8sClient.ApplyPolicy(policy); err != nil {
			log.Printf("Failed to apply policy: %v", err)
			continue
		}
	}
}
