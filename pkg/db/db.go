package db

import (
	"database/sql"

	"github.com/xUnholy/advisor-controller/k8s"

	_ "github.com/lib/pq"
)

type Client struct {
	db *sql.DB
}

func New(dataSourceName string) (*Client, error) {
	db, err := sql.Open("postgres", dataSourceName)
	if err != nil {
		return nil, err
	}

	return &Client{db}, nil
}

func (c *Client) GetPolicies(date string) ([]*k8s.Policy, error) {
	rows, err := c.db.Query(`SELECT podname, ingress, egress FROM pod_policies WHERE date = $1`, date)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var policies []*k8s.Policy
	for rows.Next() {
		policy := &k8s.Policy{}
		// Parsing logic omitted
		policies = append(policies, policy)
	}

	return policies, rows.Err()
}
