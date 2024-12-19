package apiapplication

import (
	"encoding/json"
	"strings"

	webscan "github.com/Method-Security/webscan/generated/go/app"
	common "github.com/Method-Security/webscan/generated/go/common"
	"github.com/Method-Security/webscan/utils"
)

type GraphQLLibrary struct{}

var graphqlPaths = []string{
	"/graphql",
	"/api/graphql",
	"/v1/graphql",
	"/graphql/v1",
	"/query",
	"/api",
}

func (graphqlLib *GraphQLLibrary) ModuleRun(target string, config *webscan.AppFingerprintConfig) (*webscan.AppFingerprintAttemptInfo, []string) {
	attempt := webscan.AppFingerprintAttemptInfo{
		Name:    webscan.NewAppFingerprintResourceModuleFromApiApplicationModule(webscan.ApiApplicationModuleGraphql),
		Finding: false,
	}
	errors := []string{}

	baseURL, parsedTargetPath, err := utils.SplitTarget(target)
	if err != nil {
		errors = append(errors, err.Error())
		return &attempt, errors
	}

	// GraphQL introspection query
	introspectionBodyQuery := map[string]string{
		"query": "{ __schema { queryType { name } } }",
	}
	jsonQuery, _ := json.Marshal(introspectionBodyQuery)
	bodyStr := string(jsonQuery)

	requests := []*common.RequestInfo{}
	for _, path := range graphqlPaths {
		request := utils.PerformRequestScan(baseURL, parsedTargetPath+path, common.HttpMethodPost, common.RequestParams{BodyParams: bodyStr}, config.Timeout)
		errors = append(errors, request.Errors...)

		requests = append(requests, &request)
		finding := graphqlLib.AnalyzeResponse(&request)
		if finding {
			attempt.Finding = true
		}
	}

	attempt.Requests = requests
	return &attempt, errors
}

func (graphqlLib *GraphQLLibrary) AnalyzeResponse(response *common.RequestInfo) bool {
	if response == nil {
		return false
	}

	if response.ResponseBody != nil {
		graphqlIndicators := []string{
			"__schema",
			"queryType",
		}

		var jsonResponse map[string]interface{}
		if err := json.Unmarshal([]byte(*response.ResponseBody), &jsonResponse); err == nil {
			// Check for GraphQL-specific fields in the JSON response
			for _, indicator := range graphqlIndicators {
				if strings.Contains(*response.ResponseBody, indicator) {
					return true
				}
			}
		}
	}

	return false
}
