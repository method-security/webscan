package apiapplication

import (
	// Standard
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	// Generated
	enumerateapiapplicationfern "github.com/Method-Security/webscan/generated/go/app/enumerate/apiapplication"
	common "github.com/Method-Security/webscan/generated/go/common"

	// utils
	utils "github.com/Method-Security/webscan/utils"
	request "github.com/Method-Security/webscan/utils/request"

	// External
	libopenapi "github.com/pb33f/libopenapi"
	base "github.com/pb33f/libopenapi/datamodel/high/base"
	v2 "github.com/pb33f/libopenapi/datamodel/high/v2"
	v3 "github.com/pb33f/libopenapi/datamodel/high/v3"
	orderedmap "github.com/pb33f/libopenapi/orderedmap"
	yaml "gopkg.in/yaml.v3"
)

// Common Swagger/OpenAPI endpoint paths to check
var commonSpecPaths = []string{
	"/swagger.json",
	"/api-docs/swagger.json",
	"/api/swagger.json",
	"/api/v1/swagger.json",
	"/api/v2/swagger.json",
	"/api/v3/swagger.json",
	"/swagger/v1/swagger.json",
	"/swagger/v2/swagger.json",
	"/swagger/v3/swagger.json",
	"/openapi.json",
	"/api-docs/openapi.json",
	"/api/openapi.json",
	"/api/v1/openapi.json",
	"/api/v2/openapi.json",
	"/api/v3/openapi.json",
	"/v1/swagger.json",
	"/v2/swagger.json",
	"/v3/swagger.json",
	"/docs/swagger.json",
	"/docs/openapi.json",
	"/swagger-ui/swagger.json",
	"/swagger-ui/openapi.json",
}

func createRequestConfig(baseURL, path string, timeout int) common.RequestConfig {
	return common.RequestConfig{
		BaseUrl:            baseURL,
		Path:               path,
		Method:             common.HttpMethodGet,
		RequestParams:      &common.RequestParams{},
		FollowRedirects:    false,
		MaxRedirects:       nil,
		Insecure:           true,
		Timeout:            timeout,
		RequestMethod:      common.RequestMethodStandard,
		HeadlessConfig:     nil,
		BrowserbaseConfig:  nil,
		BrowserbaseSecrets: nil,
	}
}

// PerformAppEnumerateSwagger performs a Swagger scan against a target URL and returns the report.
func PerformAppEnumerateSwagger(ctx context.Context, target string, timeout int) enumerateapiapplicationfern.RoutesReport {
	report := enumerateapiapplicationfern.RoutesReport{Target: target}

	// Normalize target URL
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
	}
	target = strings.TrimSuffix(target, "/")

	// Try each common path until we find a valid Swagger/OpenAPI spec
	var swaggerURL string
	var bodyBytes []byte
	var foundSpec bool

	for _, path := range commonSpecPaths {
		if dl, ok := ctx.Deadline(); ok {
			timeout = int(time.Until(dl).Seconds())
		}

		baseURL, parsedTargetPath, err := utils.SplitTarget(target)
		if err != nil {
			report.Errors = append(report.Errors, err.Error())
			return report
		}

		// Create a request config for the Swagger/OpenAPI spec and send the request
		requestConfig := createRequestConfig(baseURL, fmt.Sprintf("%s%s", parsedTargetPath, path), timeout)
		request, err := request.SendRequest(ctx, requestConfig)
		if err != nil {
			report.Errors = append(report.Errors, err.Error())
			return report
		}

		// Check if the request was successful
		if len(request.Errors) > 0 || request.StatusCode == nil || *request.StatusCode != 200 || request.ResponseBody == nil {
			continue
		}

		// Unmarshal the response body into a map
		var docType map[string]interface{}
		if err := json.Unmarshal([]byte(*request.ResponseBody), &docType); err != nil {
			continue
		}

		// Check if the response body contains a Swagger or OpenAPI spec
		if _, ok := docType["swagger"]; ok || docType["openapi"] != nil {
			swaggerURL = target + path // full URL for the report
			bodyBytes = []byte(*request.ResponseBody)
			foundSpec = true
			break
		}
	}

	if !foundSpec {
		report.Errors = append(report.Errors, "No valid Swagger/OpenAPI spec found")
		return report
	}

	report.SchemaUrl = &swaggerURL

	// Encode the raw body in base64 and add to the report
	report.Raw = base64.StdEncoding.EncodeToString(bodyBytes)

	// Create a new document from specification bytes
	document, err := libopenapi.NewDocument(bodyBytes)
	if err != nil {
		report.Errors = append(report.Errors, fmt.Sprintf("Error creating new document: %v", err))
		return report
	}

	// Determine if the document is Swagger (OpenAPI 2.0) or OpenAPI 3.0+
	var docType map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &docType); err != nil {
		report.Errors = append(report.Errors, fmt.Sprintf("failed to unmarshal document type: %v", err))
		return report
	}

	if version, ok := docType["swagger"]; ok && strings.HasPrefix(version.(string), "2") {
		versionStr := version.(string)
		report.Version = &versionStr
		err = handleSwaggerV2(document, &report)
	} else if version, ok := docType["openapi"]; ok && strings.HasPrefix(version.(string), "3") {
		versionStr := version.(string)
		report.Version = &versionStr
		err = handleOpenAPIV3(document, &report, target)
	} else {
		report.Errors = append(report.Errors, "unsupported OpenAPI version")
		return report
	}

	if err != nil {
		report.Errors = append(report.Errors, err.Error())
		return report
	}

	return report
}

func handleSwaggerV2(document libopenapi.Document, report *enumerateapiapplicationfern.RoutesReport) error {
	report.AppType = enumerateapiapplicationfern.ApiTypeSwaggerV2
	var errors []error
	var v2Model *libopenapi.DocumentModel[v2.Swagger]

	v2Model, errors = document.BuildV2Model()
	if len(errors) > 0 {
		for i := range errors {
			errMsg := fmt.Sprintf("error: %v", errors[i])
			report.Errors = append(report.Errors, errMsg)
		}
		return fmt.Errorf("cannot create v2 model from document: %d errors reported", len(errors))
	}

	model := v2Model.Model

	// Construct the base endpoint URL from the host and basePath fields
	baseEndpointURL := fmt.Sprintf("https://%s%s", model.Host, model.BasePath)
	report.BaseEndpointUrl = baseEndpointURL

	// Extract security definitions
	securityDefinitions := make(map[string]*v2.SecurityScheme)
	if model.SecurityDefinitions != nil {
		for pair := model.SecurityDefinitions.Definitions.Oldest(); pair != nil; pair = pair.Next() {
			securityDefinitions[pair.Key] = pair.Value
		}
	}

	// Add security schemes to the report
	report.SecuritySchemes = convertSecurityDefinitionsV2(securityDefinitions)

	// Add app-level security requirements to the report
	securityRequirements := convertSecurityRequirementsV2(model.Security)
	if securityRequirements != nil {
		report.Security = []*enumerateapiapplicationfern.SecurityRequirement{securityRequirements}
	}

	// Iterate over paths and methods to populate the report
	for pair := model.Paths.PathItems.Oldest(); pair != nil; pair = pair.Next() {
		path := pair.Key
		pathItem := pair.Value
		for opPair := pathItem.GetOperations().Oldest(); opPair != nil; opPair = opPair.Next() {
			method := opPair.Key
			operation := opPair.Value

			var responseProperties map[string][]string
			if strings.ToUpper(method) == "GET" {
				var err error
				responseProperties, err = extractResponsePropertiesV2(operation)
				if err != nil {
					responseProperties = nil
				}
			}

			requestSchema := extractRequestSchemaV2(operation, document, report)

			securityRequirements := convertSecurityRequirementsV2(operation.Security)
			route := enumerateapiapplicationfern.Route{
				Path:               path,
				Method:             method,
				QueryParams:        getQueryParamsV2(operation.Parameters),
				Security:           securityRequirements,
				Type:               enumerateapiapplicationfern.ApiTypeSwaggerV2,
				Description:        operation.Description,
				RequestSchema:      requestSchema,
				ResponseProperties: responseProperties,
			}

			report.Routes = append(report.Routes, &route)
		}
	}

	return nil
}

func handleOpenAPIV3(document libopenapi.Document, report *enumerateapiapplicationfern.RoutesReport, target string) error {
	report.AppType = enumerateapiapplicationfern.ApiTypeSwaggerV3
	var errors []error
	var v3Model *libopenapi.DocumentModel[v3.Document]

	v3Model, errors = document.BuildV3Model()
	if len(errors) > 0 {
		for i := range errors {
			errMsg := fmt.Sprintf("error: %v", errors[i])
			report.Errors = append(report.Errors, errMsg)
		}
		return fmt.Errorf("cannot create v3 model from document: %d errors reported", len(errors))
	}

	model := v3Model.Model

	// Construct the base endpoint URL from the servers array
	serverPath := ""
	if len(model.Servers) > 0 {
		serverPath = model.Servers[0].URL
	}
	parsedURL, err := url.Parse(target)
	if err != nil {
		errMsg := fmt.Sprintf("failed to parse target URL: %v", err)
		report.Errors = append(report.Errors, errMsg)
		return fmt.Errorf("failed to parse target URL: %v", err)
	}
	baseURL := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)
	baseURL = strings.TrimSuffix(baseURL, "/")
	report.BaseEndpointUrl = baseURL + serverPath

	// Extract security definitions
	securityDefinitions := make(map[string]*v3.SecurityScheme)
	for pair := model.Components.SecuritySchemes.Oldest(); pair != nil; pair = pair.Next() {
		securityDefinitions[pair.Key] = pair.Value
	}

	// Add security schemes to the report
	report.SecuritySchemes = convertSecurityDefinitionsV3(securityDefinitions)

	// Add app-level security requirements to the report
	securityRequirements := convertSecurityRequirementsV3(model.Security)
	if securityRequirements != nil {
		report.Security = []*enumerateapiapplicationfern.SecurityRequirement{securityRequirements}
	}

	// Iterate over paths and methods to populate the report
	for pair := model.Paths.PathItems.Oldest(); pair != nil; pair = pair.Next() {
		path := pair.Key
		pathItem := pair.Value
		for opPair := pathItem.GetOperations().Oldest(); opPair != nil; opPair = opPair.Next() {
			method := opPair.Key
			operation := opPair.Value

			var responseProperties map[string][]string
			if strings.ToUpper(method) == "GET" {
				var err error
				responseProperties, err = extractResponsePropertiesV3(operation)
				if err != nil {
					responseProperties = nil
				}
			}

			requestSchema := extractRequestSchemaV3(operation, document, report)

			securityRequirements := convertSecurityRequirementsV3(operation.Security)
			route := enumerateapiapplicationfern.Route{
				Path:               path,
				Method:             method,
				QueryParams:        getQueryParamsV3(operation.Parameters),
				Security:           securityRequirements,
				Type:               enumerateapiapplicationfern.ApiTypeSwaggerV3,
				Description:        operation.Description,
				RequestSchema:      requestSchema,
				ResponseProperties: responseProperties,
			}

			report.Routes = append(report.Routes, &route)
		}
	}

	return nil
}

// Helper function to get the first layer of schema properties recursively
func getSchemaPropertiesRecursive(schema *base.Schema) []string {
	var properties []string
	if schema.Properties != nil {
		for pair := schema.Properties.Oldest(); pair != nil; pair = pair.Next() {
			propName := pair.Key
			properties = append(properties, propName)
			// Recursively get properties of nested schemas
			nestedSchema := pair.Value.Schema()
			if nestedSchema != nil {
				nestedProperties := getSchemaPropertiesRecursive(nestedSchema)
				properties = append(properties, nestedProperties...)
			}
		}
	}
	return properties
}

// getQueryParamsV2 extracts query parameters from the operation parameters for Swagger (OpenAPI 2.0)
func getQueryParamsV2(params []*v2.Parameter) []string {
	var queryParams []string
	for _, param := range params {
		if param.In == "query" {
			queryParams = append(queryParams, param.Name)
		}
	}
	return queryParams
}

// getQueryParamsV3 extracts query parameters from the operation parameters for OpenAPI 3.0+
func getQueryParamsV3(params []*v3.Parameter) []string {
	var queryParams []string
	for _, param := range params {
		if param.In == "query" {
			queryParams = append(queryParams, param.Name)
		}
	}
	return queryParams
}

func convertSecurityDefinitionsV2(securityDefinitions map[string]*v2.SecurityScheme) map[string]*enumerateapiapplicationfern.SecurityScheme {
	schemes := make(map[string]*enumerateapiapplicationfern.SecurityScheme)
	for name, scheme := range securityDefinitions {
		if scheme == nil {
			continue
		}
		webscanScheme := &enumerateapiapplicationfern.SecurityScheme{
			Type:        enumerateapiapplicationfern.SecuritySchemeType(scheme.Type),
			Description: &scheme.Description,
			Name:        &name,
		}

		switch scheme.Type {
		case "apiKey":
			webscanScheme.In = &scheme.In
		case "oauth2":
			webscanScheme.Flow = &scheme.Flow
			webscanScheme.AuthorizationUrl = &scheme.AuthorizationUrl
			webscanScheme.TokenUrl = &scheme.TokenUrl
			webscanScheme.Scopes = convertV2ScopesToMap(scheme.Scopes)
		}

		if webscanScheme.Type != "" {
			schemes[name] = webscanScheme
		}

		switch scheme.Type {
		case "apiKey":
			webscanScheme.In = &scheme.In
		case "oauth2":
			webscanScheme.Flow = &scheme.Flow
			webscanScheme.AuthorizationUrl = &scheme.AuthorizationUrl
			webscanScheme.TokenUrl = &scheme.TokenUrl
			webscanScheme.Scopes = convertV2ScopesToMap(scheme.Scopes)
		}

		schemes[name] = webscanScheme
	}
	return schemes
}

func convertV2ScopesToMap(scopes *v2.Scopes) map[string]string {
	if scopes == nil {
		return nil
	}
	result := make(map[string]string)
	for pair := scopes.Values.Oldest(); pair != nil; pair = pair.Next() {
		result[pair.Key] = pair.Value
	}
	return result
}

func convertSecurityDefinitionsV3(securityDefinitions map[string]*v3.SecurityScheme) map[string]*enumerateapiapplicationfern.SecurityScheme {
	schemes := make(map[string]*enumerateapiapplicationfern.SecurityScheme)
	for name, scheme := range securityDefinitions {
		if scheme == nil {
			continue
		}
		webscanScheme := &enumerateapiapplicationfern.SecurityScheme{
			Type:        enumerateapiapplicationfern.SecuritySchemeType(scheme.Type),
			Description: &scheme.Description,
			Name:        &name,
		}

		switch scheme.Type {
		case "apiKey":
			webscanScheme.In = &scheme.In
		case "http":
			webscanScheme.Scheme = &scheme.Scheme
			webscanScheme.BearerFormat = &scheme.BearerFormat
		case "oauth2":
			webscanScheme.Flows = convertOAuthFlowsV3(scheme.Flows)
		case "openIdConnect":
			webscanScheme.OpenIdConnectUrl = &scheme.OpenIdConnectUrl
		}

		if webscanScheme.Type != "" {
			schemes[name] = webscanScheme
		}
	}
	return schemes
}

func convertOAuthFlowsV3(flows *v3.OAuthFlows) *enumerateapiapplicationfern.OAuthFlows {
	if flows == nil {
		return nil
	}
	return &enumerateapiapplicationfern.OAuthFlows{
		Implicit:          convertOAuthFlowV3(flows.Implicit),
		Password:          convertOAuthFlowV3(flows.Password),
		ClientCredentials: convertOAuthFlowV3(flows.ClientCredentials),
		AuthorizationCode: convertOAuthFlowV3(flows.AuthorizationCode),
	}
}

func convertOAuthFlowV3(flow *v3.OAuthFlow) *enumerateapiapplicationfern.OAuthFlow {
	if flow == nil {
		return nil
	}
	return &enumerateapiapplicationfern.OAuthFlow{
		AuthorizationUrl: &flow.AuthorizationUrl,
		TokenUrl:         &flow.TokenUrl,
		RefreshUrl:       &flow.RefreshUrl,
		Scopes:           convertOrderedMapToMap(flow.Scopes),
	}
}

func convertOrderedMapToMap(orderedMap *orderedmap.Map[string, string]) map[string]string {
	if orderedMap == nil {
		return nil
	}
	result := make(map[string]string)
	for pair := orderedMap.Oldest(); pair != nil; pair = pair.Next() {
		result[pair.Key] = pair.Value
	}
	return result
}

func convertSecurityRequirementsV2(security []*base.SecurityRequirement) *enumerateapiapplicationfern.SecurityRequirement {
	if len(security) == 0 {
		return nil
	}
	req := &enumerateapiapplicationfern.SecurityRequirement{
		Schemes: make(map[string][]string),
	}
	for _, secReq := range security {
		for pair := secReq.Requirements.Oldest(); pair != nil; pair = pair.Next() {
			req.Schemes[pair.Key] = pair.Value
		}
	}
	if len(req.Schemes) == 0 {
		return nil
	}
	return req
}

func convertSecurityRequirementsV3(security []*base.SecurityRequirement) *enumerateapiapplicationfern.SecurityRequirement {
	if len(security) == 0 {
		return nil
	}
	req := &enumerateapiapplicationfern.SecurityRequirement{
		Schemes: make(map[string][]string),
	}
	for _, secReq := range security {
		for pair := secReq.Requirements.Oldest(); pair != nil; pair = pair.Next() {
			req.Schemes[pair.Key] = pair.Value
		}
	}
	if len(req.Schemes) == 0 {
		return nil
	}
	return req
}

func extractResponsePropertiesV2(operation *v2.Operation) (map[string][]string, error) {
	responseProperties := make(map[string][]string)
	if operation.Responses != nil && operation.Responses.Codes != nil {
		for respPair := operation.Responses.Codes.Oldest(); respPair != nil; respPair = respPair.Next() {
			statusCode := respPair.Key
			response := respPair.Value

			if response.Schema != nil {
				schema := response.Schema.Schema()
				if schema != nil {
					properties := getSchemaPropertiesRecursive(schema)
					if len(properties) > 0 {
						responseProperties[statusCode] = properties
					}
				}
			}
		}
	}
	if len(responseProperties) == 0 {
		return nil, fmt.Errorf("no response properties found")
	}
	return responseProperties, nil
}

func extractResponsePropertiesV3(operation *v3.Operation) (map[string][]string, error) {
	responseProperties := make(map[string][]string)
	if operation.Responses != nil && operation.Responses.Codes != nil {
		for respPair := operation.Responses.Codes.Oldest(); respPair != nil; respPair = respPair.Next() {
			statusCode := respPair.Key
			response := respPair.Value

			if response.Content != nil {
				for contentPair := response.Content.Oldest(); contentPair != nil; contentPair = contentPair.Next() {
					mediaTypeObject := contentPair.Value
					if mediaTypeObject.Schema != nil {
						schema := mediaTypeObject.Schema.Schema()
						if schema != nil {
							properties := getSchemaPropertiesRecursive(schema)
							if len(properties) > 0 {
								responseProperties[statusCode] = properties
							}
						}
					}
				}
			}
		}
	}
	if len(responseProperties) == 0 {
		return nil, fmt.Errorf("no response properties found")
	}
	return responseProperties, nil
}

func convertSchemaToRequestSchema(s *base.Schema, seenSchemas map[*base.Schema]bool, report *enumerateapiapplicationfern.RoutesReport) *enumerateapiapplicationfern.RequestSchema {
	if s == nil {
		report.Errors = append(report.Errors, "Encountered nil schema")
		return nil
	}

	// Check for circular references
	if seenSchemas[s] {
		report.Errors = append(report.Errors, "Circular reference detected in schema")
		return &enumerateapiapplicationfern.RequestSchema{
			Type:        []string{"circular_reference"},
			Description: strPtr("Circular reference detected"),
		}
	}
	seenSchemas[s] = true

	rs := &enumerateapiapplicationfern.RequestSchema{
		Type:        s.Type,
		Required:    s.Required,
		Description: strPtr(s.Description),
		Format:      strPtr(s.Format),
	}

	if s.Default != nil {
		defaultStr := fmt.Sprintf("%v", s.Default)
		rs.Default = &defaultStr
	}

	if s.Example != nil {
		rs.Example = s.Example
	}

	convertEnumValues(s, rs, report)

	if s.MultipleOf != nil {
		rs.MultipleOf = s.MultipleOf
	}

	if s.Maximum != nil {
		rs.Maximum = s.Maximum
	}

	if s.ExclusiveMaximum != nil {
		if s.ExclusiveMaximum.IsA() {
			boolVal := s.ExclusiveMaximum.A
			rs.ExclusiveMaximum = &boolVal
		} else if s.ExclusiveMaximum.IsB() {
			boolVal := s.ExclusiveMaximum.B > 0
			rs.ExclusiveMaximum = &boolVal
		}
	}

	if s.Minimum != nil {
		rs.Minimum = s.Minimum
	}

	if s.ExclusiveMinimum != nil {
		if s.ExclusiveMinimum.IsA() {
			boolVal := s.ExclusiveMinimum.A
			rs.ExclusiveMinimum = &boolVal
		} else if s.ExclusiveMinimum.IsB() {
			boolVal := s.ExclusiveMinimum.B > 0
			rs.ExclusiveMinimum = &boolVal
		}
	}

	if s.MaxLength != nil {
		intVal := int(*s.MaxLength)
		rs.MaxLength = &intVal
	}

	if s.MinLength != nil {
		intVal := int(*s.MinLength)
		rs.MinLength = &intVal
	}

	if s.Pattern != "" {
		rs.Pattern = &s.Pattern
	}

	if s.MaxItems != nil {
		intVal := int(*s.MaxItems)
		rs.MaxItems = &intVal
	}

	if s.MinItems != nil {
		intVal := int(*s.MinItems)
		rs.MinItems = &intVal
	}

	if s.UniqueItems != nil {
		rs.UniqueItems = s.UniqueItems
	}

	if s.MaxProperties != nil {
		intVal := int(*s.MaxProperties)
		rs.MaxProperties = &intVal
	}

	if s.MinProperties != nil {
		intVal := int(*s.MinProperties)
		rs.MinProperties = &intVal
	}

	if s.Properties != nil {
		rs.Properties = make([]*enumerateapiapplicationfern.SchemaProperty, 0)
		for pair := s.Properties.Oldest(); pair != nil; pair = pair.Next() {
			propName := pair.Key
			propSchema := pair.Value.Schema()
			if propSchema != nil {
				required := contains(s.Required, propName)
				prop := &enumerateapiapplicationfern.SchemaProperty{
					Name:        propName,
					Type:        propSchema.Type,
					Format:      strPtr(propSchema.Format),
					Description: strPtr(propSchema.Description),
					Required:    &required,
				}
				if propSchema.Items != nil && propSchema.Items.A != nil {
					prop.Items = convertSchemaToRequestSchema(propSchema.Items.A.Schema(), seenSchemas, report)
				}
				if propSchema.Properties != nil {
					nestedSchema := convertSchemaToRequestSchema(propSchema, seenSchemas, report)
					prop.Properties = nestedSchema.Properties
				}
				rs.Properties = append(rs.Properties, prop)
			} else {
				report.Errors = append(report.Errors, fmt.Sprintf("Nil property schema for property: %s", propName))
			}
		}
	}

	if s.Items != nil && s.Items.A != nil {
		rs.Items = convertSchemaToRequestSchema(s.Items.A.Schema(), seenSchemas, report)
	}

	if s.AdditionalProperties != nil && s.AdditionalProperties.A != nil {
		rs.AdditionalProperties = convertSchemaToRequestSchema(s.AdditionalProperties.A.Schema(), seenSchemas, report)
	}

	if len(s.AllOf) > 0 {
		rs.AllOf = make([]*enumerateapiapplicationfern.RequestSchema, len(s.AllOf))
		for i, schema := range s.AllOf {
			rs.AllOf[i] = convertSchemaToRequestSchema(schema.Schema(), seenSchemas, report)
		}
	}

	if len(s.OneOf) > 0 {
		rs.OneOf = make([]*enumerateapiapplicationfern.RequestSchema, len(s.OneOf))
		for i, schema := range s.OneOf {
			rs.OneOf[i] = convertSchemaToRequestSchema(schema.Schema(), seenSchemas, report)
		}
	}

	if len(s.AnyOf) > 0 {
		rs.AnyOf = make([]*enumerateapiapplicationfern.RequestSchema, len(s.AnyOf))
		for i, schema := range s.AnyOf {
			rs.AnyOf[i] = convertSchemaToRequestSchema(schema.Schema(), seenSchemas, report)
		}
	}

	if s.Not != nil {
		rs.Not = convertSchemaToRequestSchema(s.Not.Schema(), seenSchemas, report)
	}

	delete(seenSchemas, s)
	return rs
}

func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func extractRequestSchemaV2(operation *v2.Operation, doc libopenapi.Document, report *enumerateapiapplicationfern.RoutesReport) *enumerateapiapplicationfern.RequestSchema {
	if operation.Parameters == nil {
		report.Errors = append(report.Errors, "No parameters found in operation")
		return nil
	}

	for _, param := range operation.Parameters {
		if param.In == "body" && param.Schema != nil {
			if s := param.Schema.Schema(); s != nil {
				return convertSchemaToRequestSchema(s, make(map[*base.Schema]bool), report)
			}
		}
	}
	report.Errors = append(report.Errors, "No body parameter with schema found in operation")
	return nil
}

func extractRequestSchemaV3(operation *v3.Operation, doc libopenapi.Document, report *enumerateapiapplicationfern.RoutesReport) *enumerateapiapplicationfern.RequestSchema {
	if operation.RequestBody == nil || operation.RequestBody.Content == nil {
		report.Errors = append(report.Errors, "No request body or content found in operation")
		return nil
	}

	for pair := operation.RequestBody.Content.Oldest(); pair != nil; pair = pair.Next() {
		mediaType := pair.Value
		if mediaType.Schema != nil {
			if s := mediaType.Schema.Schema(); s != nil {
				return convertSchemaToRequestSchema(s, make(map[*base.Schema]bool), report)
			}
		}
	}
	report.Errors = append(report.Errors, "No schema found in request body content")
	return nil
}

func convertEnumValues(s *base.Schema, rs *enumerateapiapplicationfern.RequestSchema, report *enumerateapiapplicationfern.RoutesReport) {
	if len(s.Enum) > 0 {
		rs.Enum = make([]interface{}, len(s.Enum))
		for i, v := range s.Enum {
			rs.Enum[i] = convertEnumValue(v, report)
		}
	}
}

func convertEnumValue(v *yaml.Node, report *enumerateapiapplicationfern.RoutesReport) interface{} {
	switch v.Kind {
	case yaml.ScalarNode:
		switch v.Tag {
		case "!!str":
			return v.Value
		case "!!int":
			val, err := strconv.ParseInt(v.Value, 10, 64)
			if err == nil {
				return val
			}
			report.Errors = append(report.Errors, fmt.Sprintf("Failed to parse int enum value: %s", err))
		case "!!float":
			val, err := strconv.ParseFloat(v.Value, 64)
			if err == nil {
				return val
			}
			report.Errors = append(report.Errors, fmt.Sprintf("Failed to parse float enum value: %s", err))
		case "!!bool":
			val, err := strconv.ParseBool(v.Value)
			if err == nil {
				return val
			}
			report.Errors = append(report.Errors, fmt.Sprintf("Failed to parse bool enum value: %s", err))
		}
	case yaml.SequenceNode, yaml.MappingNode:
		// For complex types, we return them as is
		return v
	}
	return v.Value // fallback to string
}
