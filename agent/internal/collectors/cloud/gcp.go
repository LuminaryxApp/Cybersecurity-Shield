package cloud

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os/exec"
	"strings"
)

type GCPScanner struct{}

func NewGCPScanner() *GCPScanner {
	return &GCPScanner{}
}

func (s *GCPScanner) Name() string {
	return "gcp"
}

func (s *GCPScanner) Provider() Provider {
	return ProviderGCP
}

func (s *GCPScanner) Scan(ctx context.Context) ([]Finding, error) {
	if !s.isAvailable() {
		log.Println("gcp scanner: gcloud CLI not available, skipping")
		return nil, nil
	}

	var findings []Finding

	fwFindings := s.checkFirewallRules(ctx)
	findings = append(findings, fwFindings...)

	bucketFindings := s.checkStorageBuckets(ctx)
	findings = append(findings, bucketFindings...)

	saFindings := s.checkServiceAccounts(ctx)
	findings = append(findings, saFindings...)

	return findings, nil
}

func (s *GCPScanner) isAvailable() bool {
	_, err := exec.LookPath("gcloud")
	return err == nil
}

func (s *GCPScanner) checkFirewallRules(ctx context.Context) []Finding {
	out, err := exec.CommandContext(ctx, "gcloud", "compute", "firewall-rules", "list",
		"--format=json").Output()
	if err != nil {
		return nil
	}

	var rules []struct {
		Name         string   `json:"name"`
		Direction    string   `json:"direction"`
		SourceRanges []string `json:"sourceRanges"`
		Allowed      []struct {
			IPProtocol string   `json:"IPProtocol"`
			Ports      []string `json:"ports"`
		} `json:"allowed"`
		Disabled bool `json:"disabled"`
	}
	if err := json.Unmarshal(out, &rules); err != nil {
		return nil
	}

	var findings []Finding
	for _, rule := range rules {
		if rule.Disabled {
			continue
		}
		if rule.Direction != "INGRESS" {
			continue
		}

		hasOpenSource := false
		for _, src := range rule.SourceRanges {
			if src == "0.0.0.0/0" {
				hasOpenSource = true
				break
			}
		}
		if !hasOpenSource {
			continue
		}

		for _, allow := range rule.Allowed {
			severity := "medium"
			for _, port := range allow.Ports {
				if port == "22" || port == "3389" {
					severity = "critical"
				}
			}
			if allow.IPProtocol == "all" {
				severity = "critical"
			}

			portStr := strings.Join(allow.Ports, ",")
			if portStr == "" {
				portStr = "all"
			}

			f := NewFinding(ProviderGCP, "firewall", rule.Name, "misconfiguration",
				severity,
				"Firewall rule "+rule.Name+" allows ingress from 0.0.0.0/0",
				"Restrict source ranges to specific IP addresses or CIDR blocks")
			f.Metadata["protocol"] = allow.IPProtocol
			f.Metadata["ports"] = portStr
			findings = append(findings, f)
		}
	}

	return findings
}

func (s *GCPScanner) checkStorageBuckets(ctx context.Context) []Finding {
	out, err := exec.CommandContext(ctx, "gsutil", "ls").Output()
	if err != nil {
		return nil
	}

	buckets := strings.Split(strings.TrimSpace(string(out)), "\n")
	var findings []Finding

	for _, bucket := range buckets {
		bucket = strings.TrimSpace(bucket)
		if bucket == "" {
			continue
		}

		iamOut, err := exec.CommandContext(ctx, "gsutil", "iam", "get", bucket).Output()
		if err != nil {
			continue
		}

		iamPolicy := string(iamOut)
		if strings.Contains(iamPolicy, "allUsers") || strings.Contains(iamPolicy, "allAuthenticatedUsers") {
			bucketName := strings.TrimPrefix(bucket, "gs://")
			bucketName = strings.TrimSuffix(bucketName, "/")

			findings = append(findings, NewFinding(ProviderGCP, "storage", bucketName, "misconfiguration",
				"critical",
				"Storage bucket "+bucketName+" is publicly accessible",
				"Remove allUsers and allAuthenticatedUsers from the bucket IAM policy"))
		}
	}

	return findings
}

func (s *GCPScanner) checkServiceAccounts(ctx context.Context) []Finding {
	out, err := exec.CommandContext(ctx, "gcloud", "iam", "service-accounts", "list",
		"--format=json").Output()
	if err != nil {
		return nil
	}

	var accounts []struct {
		Email    string `json:"email"`
		Disabled bool   `json:"disabled"`
	}
	if err := json.Unmarshal(out, &accounts); err != nil {
		return nil
	}

	var findings []Finding
	for _, acct := range accounts {
		if acct.Disabled {
			continue
		}

		keysOut, err := exec.CommandContext(ctx, "gcloud", "iam", "service-accounts", "keys", "list",
			"--iam-account", acct.Email, "--format=json").Output()
		if err != nil {
			continue
		}

		var keys []struct {
			KeyType     string `json:"keyType"`
			ValidBefore string `json:"validBeforeTime"`
		}
		if err := json.Unmarshal(keysOut, &keys); err != nil {
			continue
		}

		userKeyCount := 0
		for _, key := range keys {
			if key.KeyType == "USER_MANAGED" {
				userKeyCount++
			}
		}

		if userKeyCount > 0 {
			findings = append(findings, NewFinding(ProviderGCP, "iam-sa", acct.Email, "credential_hygiene",
				"medium",
				"Service account "+acct.Email+" has "+fmt.Sprintf("%d", userKeyCount)+" user-managed key(s)",
				"Use workload identity or short-lived credentials instead of user-managed keys"))
		}
	}

	return findings
}
