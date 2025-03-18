package cloudbucket

import (
	webscan "github.com/Method-Security/webscan/generated/go/app"
	common "github.com/Method-Security/webscan/generated/go/common"
)

type AwsS3Library struct{}

func (awsLib *AwsS3Library) Name() *webscan.AppFingerprintResourceModule {
	return webscan.NewAppFingerprintResourceModuleFromCloudBucketModule(webscan.CloudBucketModuleAwss3)
}

func (awsLib *AwsS3Library) Paths() []string {
	paths := []string{
		"", // Root
	}
	return paths
}

func (awsLib *AwsS3Library) RequestParams() (common.HttpMethod, common.RequestParams) {
	return common.HttpMethodGet, common.RequestParams{}
}

func (awsLib *AwsS3Library) HeaderIndicators() map[string][]string {
	return map[string][]string{
		"server":              {"amazons3"},
		"x-amz-bucket-region": {""},
	}
}

func (awsLib *AwsS3Library) BodyIndicators() []string {
	return []string{}
}
