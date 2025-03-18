package apiapplication

import (
	"encoding/json"

	webscan "github.com/Method-Security/webscan/generated/go/app"
	common "github.com/Method-Security/webscan/generated/go/common"
)

type GraphQLLibrary struct{}

func (graphqlLib *GraphQLLibrary) Name() *webscan.AppFingerprintResourceModule {
	return webscan.NewAppFingerprintResourceModuleFromApiApplicationModule(webscan.ApiApplicationModuleGraphql)
}

func (graphqlLib *GraphQLLibrary) Paths() []string {
	paths := []string{
		"/graphql",
		"/api/graphql",
		"/v1/graphql",
		"/graphql/v1",
		"/query",
		"/api",
	}
	return paths
}

func (graphqlLib *GraphQLLibrary) RequestParams() (common.HttpMethod, common.RequestParams) {
	// GraphQL introspection query
	introspectionBodyQuery := map[string]string{
		"query": "{ __schema { queryType { name } } }",
	}
	jsonQuery, _ := json.Marshal(introspectionBodyQuery)
	bodyStr := string(jsonQuery)

	return common.HttpMethodPost, common.RequestParams{BodyParams: bodyStr}
}

func (graphqlLib *GraphQLLibrary) HeaderIndicators() map[string][]string {
	return map[string][]string{}
}

func (graphqlLib *GraphQLLibrary) BodyIndicators() []string {
	return []string{
		"__schema",
		"queryType",
	}
}
