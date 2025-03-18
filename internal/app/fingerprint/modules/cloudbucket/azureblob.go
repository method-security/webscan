package cloudbucket

import (
	webscan "github.com/Method-Security/webscan/generated/go/app"
	common "github.com/Method-Security/webscan/generated/go/common"
)

type AzureBlobLibrary struct{}

func (azureLib *AzureBlobLibrary) Name() *webscan.AppFingerprintResourceModule {
	return webscan.NewAppFingerprintResourceModuleFromCloudBucketModule(webscan.CloudBucketModuleAzureblob)
}

func (azureLib *AzureBlobLibrary) Paths() []string {
	paths := []string{
		"", // Root
	}
	return paths
}

func (azureLib *AzureBlobLibrary) RequestParams() (common.HttpMethod, common.RequestParams) {
	return common.HttpMethodGet, common.RequestParams{}
}

func (azureLib *AzureBlobLibrary) HeaderIndicators() map[string][]string {
	return map[string][]string{
		"server":         {"blob"},
		"x-ms-blob-type": {""},
	}
}

func (azureLib *AzureBlobLibrary) BodyIndicators() []string {
	return []string{}
}
