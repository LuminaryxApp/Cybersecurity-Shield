package cloud

import (
	"context"
	"encoding/json"
	"log"
	"os/exec"
	"strings"
)

type AzureScanner struct{}

func NewAzureScanner() *AzureScanner {
	return &AzureScanner{}
}

func (s *AzureScanner) Name() string {
	return "azure"
}

func (s *AzureScanner) Provider() Provider {
	return ProviderAzure
}

func (s *AzureScanner) Scan(ctx context.Context) ([]Finding, error) {
	if !s.isAvailable() {
		log.Println("azure scanner: Azure CLI not available, skipping")
		return nil, nil
	}

	var findings []Finding

	nsgFindings := s.checkNSGs(ctx)
	findings = append(findings, nsgFindings...)

	storageFindings := s.checkStorageAccounts(ctx)
	findings = append(findings, storageFindings...)

	sqlFindings := s.checkSQLServers(ctx)
	findings = append(findings, sqlFindings...)

	return findings, nil
}

func (s *AzureScanner) isAvailable() bool {
	_, err := exec.LookPath("az")
	return err == nil
}

func (s *AzureScanner) checkNSGs(ctx context.Context) []Finding {
	out, err := exec.CommandContext(ctx, "az", "network", "nsg", "list", "--output", "json").Output()
	if err != nil {
		return nil
	}

	var nsgs []struct {
		Name          string `json:"name"`
		ID            string `json:"id"`
		SecurityRules []struct {
			Name                   string `json:"name"`
			Access                 string `json:"access"`
			Direction              string `json:"direction"`
			SourceAddressPrefix    string `json:"sourceAddressPrefix"`
			DestinationPortRange   string `json:"destinationPortRange"`
			Protocol               string `json:"protocol"`
		} `json:"securityRules"`
	}
	if err := json.Unmarshal(out, &nsgs); err != nil {
		return nil
	}

	var findings []Finding
	for _, nsg := range nsgs {
		for _, rule := range nsg.SecurityRules {
			if rule.Direction == "Inbound" && rule.Access == "Allow" &&
				(rule.SourceAddressPrefix == "*" || rule.SourceAddressPrefix == "0.0.0.0/0" ||
					rule.SourceAddressPrefix == "Internet") {
				severity := "medium"
				if rule.DestinationPortRange == "22" || rule.DestinationPortRange == "3389" {
					severity = "critical"
				}
				if rule.DestinationPortRange == "*" {
					severity = "critical"
				}

				f := NewFinding(ProviderAzure, "nsg", nsg.Name, "misconfiguration",
					severity,
					"NSG "+nsg.Name+" rule "+rule.Name+" allows inbound from any source",
					"Restrict the source address prefix to specific IP ranges")
				f.Metadata["rule_name"] = rule.Name
				f.Metadata["port_range"] = rule.DestinationPortRange
				f.Metadata["protocol"] = rule.Protocol
				findings = append(findings, f)
			}
		}
	}

	return findings
}

func (s *AzureScanner) checkStorageAccounts(ctx context.Context) []Finding {
	out, err := exec.CommandContext(ctx, "az", "storage", "account", "list", "--output", "json").Output()
	if err != nil {
		return nil
	}

	var accounts []struct {
		Name              string `json:"name"`
		ID                string `json:"id"`
		EnableHTTPSOnly   bool   `json:"enableHttpsTrafficOnly"`
		AllowBlobPublic   bool   `json:"allowBlobPublicAccess"`
		NetworkRuleSet    struct {
			DefaultAction string `json:"defaultAction"`
		} `json:"networkRuleSet"`
	}
	if err := json.Unmarshal(out, &accounts); err != nil {
		return nil
	}

	var findings []Finding
	for _, acct := range accounts {
		if !acct.EnableHTTPSOnly {
			findings = append(findings, NewFinding(ProviderAzure, "storage", acct.Name, "misconfiguration",
				"high",
				"Storage account "+acct.Name+" does not enforce HTTPS-only traffic",
				"Enable 'Secure transfer required' on the storage account"))
		}

		if acct.AllowBlobPublic {
			findings = append(findings, NewFinding(ProviderAzure, "storage", acct.Name, "misconfiguration",
				"critical",
				"Storage account "+acct.Name+" allows public blob access",
				"Disable public blob access on the storage account"))
		}

		if strings.ToLower(acct.NetworkRuleSet.DefaultAction) == "allow" {
			findings = append(findings, NewFinding(ProviderAzure, "storage", acct.Name, "misconfiguration",
				"medium",
				"Storage account "+acct.Name+" network rules default to allow",
				"Set the default network rule action to Deny and add specific allow rules"))
		}
	}

	return findings
}

func (s *AzureScanner) checkSQLServers(ctx context.Context) []Finding {
	out, err := exec.CommandContext(ctx, "az", "sql", "server", "list", "--output", "json").Output()
	if err != nil {
		return nil
	}

	var servers []struct {
		Name                string `json:"name"`
		FullyQualifiedName  string `json:"fullyQualifiedDomainName"`
		ResourceGroup       string `json:"resourceGroup"`
	}
	if err := json.Unmarshal(out, &servers); err != nil {
		return nil
	}

	var findings []Finding
	for _, srv := range servers {
		fwOut, err := exec.CommandContext(ctx, "az", "sql", "server", "firewall-rule", "list",
			"--server", srv.Name, "--resource-group", srv.ResourceGroup, "--output", "json").Output()
		if err != nil {
			continue
		}

		var rules []struct {
			Name           string `json:"name"`
			StartIPAddress string `json:"startIpAddress"`
			EndIPAddress   string `json:"endIpAddress"`
		}
		if err := json.Unmarshal(fwOut, &rules); err != nil {
			continue
		}

		for _, rule := range rules {
			if rule.StartIPAddress == "0.0.0.0" && rule.EndIPAddress == "255.255.255.255" {
				findings = append(findings, NewFinding(ProviderAzure, "sql-server", srv.Name, "misconfiguration",
					"critical",
					"SQL Server "+srv.Name+" has a firewall rule allowing all IP addresses",
					"Remove the overly permissive firewall rule and restrict access"))
			}
			if rule.StartIPAddress == "0.0.0.0" && rule.EndIPAddress == "0.0.0.0" {
				findings = append(findings, NewFinding(ProviderAzure, "sql-server", srv.Name, "misconfiguration",
					"medium",
					"SQL Server "+srv.Name+" allows access from Azure services",
					"Review if Azure service access is needed; disable if not required"))
			}
		}
	}

	return findings
}
