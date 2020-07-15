// Copyright Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package platform

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"

	"istio.io/pkg/log"
)

const (
	AzureMetadataEndpoint  = "http://169.254.169.254"
	AzureInstanceURL       = AzureMetadataEndpoint + "/metadata/instance"
	AzureDefaultAPIVersion = "2019-08-15"
	SysVendorPath          = "/sys/class/dmi/id/sys_vendor"
	MicrosoftIdentifier    = "Microsoft Corporation"

	AzureName     = "azure_name"
	AzureLocation = "azure_location"
	AzureVMID     = "azure_vm_id"
)

var (
	azureAPIVersionsFn = func() string {
		return metadataRequest("")
	}
	azureMetadataFn = func(version string) string {
		return metadataRequest(fmt.Sprintf("api-version=%s", version))
	}
)

type azureEnv struct {
	APIVersion      string
	computeMetadata map[string]interface{}
	networkMetadata map[string]interface{}
}

// IsAzure returns whether or not the platform for bootstrapping is Azure
// Checks the system vendor file (similar to https://github.com/banzaicloud/satellite/blob/master/providers/azure.go)
func IsAzure() bool {
	sysVendor, err := ioutil.ReadFile(SysVendorPath)
	if err != nil {
		log.Warnf("Error reading sys_vendor in Azure platform detection: %v", err)
	}
	return strings.Contains(string(sysVendor), MicrosoftIdentifier)
}

// Attempts to update the API version.
// Newer API versions can contain additional metadata fields
func (e *azureEnv) updateAPIVersion() {
	bodyJSON := stringToJSON(azureAPIVersionsFn())
	if newestVersions, ok := bodyJSON["newest-versions"]; ok {
		for _, version := range newestVersions.([]interface{}) {
			if strings.Compare(version.(string), e.APIVersion) > 0 {
				e.APIVersion = version.(string)
			}
		}
	}
}

// NewAzure returns a platform environment for Azure
func NewAzure() Environment {
	e := &azureEnv{APIVersion: AzureDefaultAPIVersion}
	e.updateAPIVersion()
	e.parseMetadata(e.azureMetadata())
	return e
}

// Retrieves Azure instance metadata response body stores it in the Azure environment
func (e *azureEnv) parseMetadata(metadata string) {
	bodyJSON := stringToJSON(metadata)
	if computeMetadata, ok := bodyJSON["compute"]; ok {
		e.computeMetadata = computeMetadata.(map[string]interface{})
	}
	if networkMetadata, ok := bodyJSON["network"]; ok {
		e.networkMetadata = networkMetadata.(map[string]interface{})
	}
}

// Generic Azure metadata GET request helper for the response body
// Uses the default timeout for the HTTP get request
func metadataRequest(query string) string {
	client := http.Client{Timeout: defaultTimeout}
	req, err := http.NewRequest("GET", fmt.Sprintf("%s?%s", AzureInstanceURL, query), nil)
	if err != nil {
		log.Warnf("Failed to create HTTP request: %v", err)
		return ""
	}
	req.Header.Add("Metadata", "True")

	response, err := client.Do(req)
	if err != nil {
		log.Warnf("HTTP request failed: %v", err)
		return ""
	}
	if response.StatusCode != http.StatusOK {
		log.Warnf("HTTP request unsuccessful with status: %v", response.Status)
	}
	defer response.Body.Close()
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Warnf("Could not read response body: %v", err)
		return ""
	}
	return string(body)
}

func stringToJSON(s string) map[string]interface{} {
	var stringJSON map[string]interface{}
	if err := json.Unmarshal([]byte(s), &stringJSON); err != nil {
		log.Warnf("Could not unmarshal response: %v:", err)
	}
	return stringJSON
}

// Returns Azure instance metadata. Must be run on an Azure VM
func (e *azureEnv) Metadata() map[string]string {
	md := map[string]string{}
	if an := e.azureName(); an != "" {
		md[AzureName] = an
	}
	if al := e.azureLocation(); al != "" {
		md[AzureLocation] = al
	}
	if aid := e.azureVMID(); aid != "" {
		md[AzureVMID] = aid
	}
	for k, v := range e.azureTags() {
		md[k] = v
	}
	return md
}

// Locality returns the region and zone
func (e *azureEnv) Locality() *core.Locality {
	var l core.Locality
	l.Region = e.azureLocation()
	l.Zone = e.azureZone()
	return &l
}

func (e *azureEnv) azureMetadata() string {
	return azureMetadataFn(e.APIVersion)
}

func (e *azureEnv) azureName() string {
	if an, ok := e.computeMetadata["name"]; ok {
		return an.(string)
	}
	return ""
}

// Returns the Azure tags prefixed by "azure_"
func (e *azureEnv) azureTags() map[string]string {
	tags := map[string]string{}
	if at, ok := e.computeMetadata["tags"]; ok && len(at.(string)) > 0 {
		for _, tag := range strings.Split(at.(string), ";") {
			kv := strings.Split(tag, ":")
			tags["azure_"+kv[0]] = kv[1]
		}
	}
	return tags
}

func (e *azureEnv) azureLocation() string {
	if al, ok := e.computeMetadata["location"]; ok {
		return al.(string)
	}
	return ""
}

func (e *azureEnv) azureZone() string {
	if az, ok := e.computeMetadata["zone"]; ok {
		return az.(string)
	}
	return ""
}

func (e *azureEnv) azureVMID() string {
	if aid, ok := e.computeMetadata["vmId"]; ok {
		return aid.(string)
	}
	return ""
}
