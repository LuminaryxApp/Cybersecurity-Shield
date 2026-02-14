package cloud

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"
)

type AWSScanner struct{}

func NewAWSScanner() *AWSScanner {
	return &AWSScanner{}
}

func (s *AWSScanner) Name() string {
	return "aws"
}

func (s *AWSScanner) Provider() Provider {
	return ProviderAWS
}

func (s *AWSScanner) Scan(ctx context.Context) ([]Finding, error) {
	if !s.isAvailable() {
		log.Println("aws scanner: AWS CLI not available, skipping")
		return nil, nil
	}

	var findings []Finding

	bucketFindings := s.checkS3Buckets(ctx)
	findings = append(findings, bucketFindings...)

	sgFindings := s.checkSecurityGroups(ctx)
	findings = append(findings, sgFindings...)

	iamFindings := s.checkIAMPolicies(ctx)
	findings = append(findings, iamFindings...)

	return findings, nil
}

func (s *AWSScanner) isAvailable() bool {
	_, err := exec.LookPath("aws")
	if err != nil {
		return false
	}
	if os.Getenv("AWS_ACCESS_KEY_ID") != "" || os.Getenv("AWS_PROFILE") != "" {
		return true
	}
	home, _ := os.UserHomeDir()
	if home != "" {
		if _, err := os.Stat(home + "/.aws/credentials"); err == nil {
			return true
		}
	}
	return false
}

func (s *AWSScanner) checkS3Buckets(ctx context.Context) []Finding {
	out, err := exec.CommandContext(ctx, "aws", "s3api", "list-buckets", "--output", "json").Output()
	if err != nil {
		return nil
	}

	var result struct {
		Buckets []struct {
			Name string `json:"Name"`
		} `json:"Buckets"`
	}
	if err := json.Unmarshal(out, &result); err != nil {
		return nil
	}

	var findings []Finding
	for _, bucket := range result.Buckets {
		aclOut, err := exec.CommandContext(ctx, "aws", "s3api", "get-bucket-acl",
			"--bucket", bucket.Name, "--output", "json").Output()
		if err != nil {
			continue
		}

		var acl struct {
			Grants []struct {
				Grantee struct {
					URI string `json:"URI"`
				} `json:"Grantee"`
				Permission string `json:"Permission"`
			} `json:"Grants"`
		}
		if err := json.Unmarshal(aclOut, &acl); err != nil {
			continue
		}

		for _, grant := range acl.Grants {
			if strings.Contains(grant.Grantee.URI, "AllUsers") ||
				strings.Contains(grant.Grantee.URI, "AuthenticatedUsers") {
				f := NewFinding(ProviderAWS, "s3", bucket.Name, "misconfiguration",
					"critical",
					"S3 bucket "+bucket.Name+" has public access via ACL",
					"Remove public access grants from the bucket ACL and enable Block Public Access")
				f.Metadata["grant_permission"] = grant.Permission
				f.Metadata["grantee_uri"] = grant.Grantee.URI
				findings = append(findings, f)
			}
		}

		policyOut, err := exec.CommandContext(ctx, "aws", "s3api", "get-bucket-policy",
			"--bucket", bucket.Name, "--output", "json").Output()
		if err == nil {
			policy := string(policyOut)
			if strings.Contains(policy, `"*"`) && strings.Contains(policy, `"Effect":"Allow"`) {
				findings = append(findings, NewFinding(ProviderAWS, "s3", bucket.Name, "misconfiguration",
					"high",
					"S3 bucket "+bucket.Name+" has an overly permissive bucket policy",
					"Review and restrict the bucket policy to specific principals"))
			}
		}
	}

	return findings
}

func (s *AWSScanner) checkSecurityGroups(ctx context.Context) []Finding {
	out, err := exec.CommandContext(ctx, "aws", "ec2", "describe-security-groups", "--output", "json").Output()
	if err != nil {
		return nil
	}

	var result struct {
		SecurityGroups []struct {
			GroupID   string `json:"GroupId"`
			GroupName string `json:"GroupName"`
			IPPerms   []struct {
				FromPort   int    `json:"FromPort"`
				ToPort     int    `json:"ToPort"`
				IPProtocol string `json:"IpProtocol"`
				IPRanges   []struct {
					CidrIP string `json:"CidrIp"`
				} `json:"IpRanges"`
			} `json:"IpPermissions"`
		} `json:"SecurityGroups"`
	}
	if err := json.Unmarshal(out, &result); err != nil {
		return nil
	}

	var findings []Finding
	for _, sg := range result.SecurityGroups {
		for _, perm := range sg.IPPerms {
			for _, ipRange := range perm.IPRanges {
				if ipRange.CidrIP == "0.0.0.0/0" {
					severity := "medium"
					if perm.FromPort == 22 || perm.FromPort == 3389 {
						severity = "critical"
					}
					if perm.IPProtocol == "-1" {
						severity = "critical"
					}

					f := NewFinding(ProviderAWS, "ec2-sg", sg.GroupID, "misconfiguration",
						severity,
						"Security group "+sg.GroupName+" allows inbound from 0.0.0.0/0",
						"Restrict inbound rules to specific IP ranges or security groups")
					f.Metadata["from_port"] = perm.FromPort
					f.Metadata["to_port"] = perm.ToPort
					f.Metadata["protocol"] = perm.IPProtocol
					findings = append(findings, f)
				}
			}
		}
	}

	return findings
}

func (s *AWSScanner) checkIAMPolicies(ctx context.Context) []Finding {
	out, err := exec.CommandContext(ctx, "aws", "iam", "list-users", "--output", "json").Output()
	if err != nil {
		return nil
	}

	var result struct {
		Users []struct {
			UserName string `json:"UserName"`
		} `json:"Users"`
	}
	if err := json.Unmarshal(out, &result); err != nil {
		return nil
	}

	var findings []Finding
	for _, user := range result.Users {
		keysOut, err := exec.CommandContext(ctx, "aws", "iam", "list-access-keys",
			"--user-name", user.UserName, "--output", "json").Output()
		if err != nil {
			continue
		}

		var keys struct {
			Metadata []struct {
				Status     string `json:"Status"`
				CreateDate string `json:"CreateDate"`
			} `json:"AccessKeyMetadata"`
		}
		if err := json.Unmarshal(keysOut, &keys); err != nil {
			continue
		}

		for _, key := range keys.Metadata {
			if key.Status == "Active" && isOlderThan90Days(key.CreateDate) {
				findings = append(findings, NewFinding(ProviderAWS, "iam", user.UserName, "credential_hygiene",
					"medium",
					"IAM user "+user.UserName+" has access keys older than 90 days",
					"Rotate the access key and update any applications using it"))
			}
		}

		mfaOut, err := exec.CommandContext(ctx, "aws", "iam", "list-mfa-devices",
			"--user-name", user.UserName, "--output", "json").Output()
		if err != nil {
			continue
		}

		var mfa struct {
			Devices []struct{} `json:"MFADevices"`
		}
		if err := json.Unmarshal(mfaOut, &mfa); err != nil {
			continue
		}

		if len(mfa.Devices) == 0 {
			findings = append(findings, NewFinding(ProviderAWS, "iam", user.UserName, "credential_hygiene",
				"high",
				"IAM user "+user.UserName+" does not have MFA enabled",
				"Enable MFA for the IAM user to add an extra layer of security"))
		}
	}

	return findings
}

func isOlderThan90Days(dateStr string) bool {
	t, err := time.Parse("2006-01-02T15:04:05Z", dateStr)
	if err != nil {
		t, err = time.Parse(time.RFC3339, dateStr)
		if err != nil {
			return false
		}
	}
	return time.Since(t) > 90*24*time.Hour
}
