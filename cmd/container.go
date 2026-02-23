package cmd

import (
	"cybedefend-cli/pkg/api"
	"cybedefend-cli/pkg/logger"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

// ── Parent command ───────────────────────────────────────────────────

var containerCmd = &cobra.Command{
	Use:   "container",
	Short: "Container image scanning",
	Long:  "Start container image vulnerability scans across different registries (GitLab, GitHub, DockerHub, GCR, ECR, ACR, Quay, Harbor, JFrog).",
}

var containerScanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Start a container scan",
	Long:  "Start a container image scan for a specific registry.",
}

// registryInfo maps registry CLI names to their API type and description.
type registryInfo struct {
	apiType           api.RegistryType
	name              string
	requireCredential bool
}

var registries = map[string]registryInfo{
	"gitlab":    {api.RegistryGitLab, "GitLab Container Registry", true},
	"github":    {api.RegistryGitHub, "GitHub Container Registry (GHCR)", false},
	"dockerhub": {api.RegistryDockerHub, "DockerHub", true},
	"gcr":       {api.RegistryGCR, "Google Container Registry (GCR)", true},
	"ecr":       {api.RegistryECR, "Amazon Elastic Container Registry (ECR)", true},
	"acr":       {api.RegistryACR, "Azure Container Registry (ACR)", true},
	"quay":      {api.RegistryQuay, "Quay.io", true},
	"harbor":    {api.RegistryHarbor, "Harbor", true},
	"jfrog":     {api.RegistryJFrog, "JFrog Artifactory", true},
}

func makeContainerScanCommand(cliName string, info registryInfo) *cobra.Command {
	cmd := &cobra.Command{
		Use:   cliName,
		Short: "Start " + info.name + " container scan",
		Run: func(cmd *cobra.Command, args []string) {
			projectID := getProjectID(cmd)
			imageName, _ := cmd.Flags().GetString("image")
			credentialID, _ := cmd.Flags().GetString("credential-id")
			branch, _ := cmd.Flags().GetString("branch")
			privateScan, _ := cmd.Flags().GetBool("private")
			severitiesStr, _ := cmd.Flags().GetString("severities")

			if imageName == "" {
				logger.Error("--image is required (e.g. my-app:v1.0.0)")
				os.Exit(1)
			}

			if info.requireCredential && credentialID == "" {
				logger.Error("--credential-id is required for %s", info.name)
				os.Exit(1)
			}

			reqBody := &api.ContainerScanRequest{
				ImageName: imageName,
			}
			if credentialID != "" {
				reqBody.CredentialID = credentialID
			}
			if branch != "" {
				reqBody.Branch = branch
			}
			if cmd.Flags().Changed("private") {
				reqBody.PrivateScan = &privateScan
			}
			if severitiesStr != "" {
				reqBody.Severities = strings.Split(strings.ToUpper(severitiesStr), ",")
			}

			client := newClientFromConfig()
			result, err := client.StartContainerScan(info.apiType, projectID, reqBody)
			if err != nil {
				logger.Error("Failed to start %s container scan: %v", info.name, err)
				os.Exit(1)
			}

			logger.Success("Container scan started!")
			printJSON(result)
		},
	}

	cmd.Flags().String("project-id", "", "Project ID")
	cmd.Flags().String("image", "", "Image name with tag (e.g. my-app:v1.0.0) (required)")
	cmd.Flags().String("credential-id", "", "Credential ID for authentication")
	cmd.Flags().String("branch", "", "Branch name for tracking")
	cmd.Flags().Bool("private", false, "Private scan results")
	cmd.Flags().String("severities", "", "Comma-separated severities (e.g. CRITICAL,HIGH)")

	return cmd
}

func init() {
	for name, info := range registries {
		containerScanCmd.AddCommand(makeContainerScanCommand(name, info))
	}

	containerCmd.AddCommand(containerScanCmd)
}
