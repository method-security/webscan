package apiapplication

import (
	"strings"

	webscan "github.com/Method-Security/webscan/generated/go/app"
	common "github.com/Method-Security/webscan/generated/go/common"
	"github.com/Method-Security/webscan/utils"
)

type GrpcLibrary struct{}

var grpcPaths = []string{
	"/grpc.health.v1.Health/Check",
	"/grpc.health.v1alpha.Health/Check",
	"/grpc.health.v1beta.Health/Check",
	"/grpc.reflection.v1alpha.ServerReflectionInfo",
	"/grpc.reflection.v1.ServerReflectionInfo",
	"/grpc.reflection.v1beta.ServerReflectionInfo",
	"/auth.Authentication/Login",
	"/user.UserService/GetUser",
}

var grpcHeaders = map[string]string{
	"Content-Type": "application/grpc",
}

func (grpcLib *GrpcLibrary) ModuleRun(target string, config *webscan.AppFingerprintConfig) (*webscan.AppFingerprintAttemptInfo, []string) {
	attempt := webscan.AppFingerprintAttemptInfo{
		Name:    webscan.NewAppFingerprintResourceModuleFromApiApplicationModule(webscan.ApiApplicationModuleGrpc),
		Finding: false,
	}
	errors := []string{}

	baseURL, parsedTargetPath, err := utils.SplitTarget(target)
	if err != nil {
		errors = append(errors, err.Error())
		return &attempt, errors
	}

	requests := []*common.RequestInfo{}
	for _, path := range grpcPaths {
		request := utils.PerformRequestScan(baseURL, parsedTargetPath+path, common.HttpMethodPost, common.RequestParams{HeaderParams: grpcHeaders, BodyParams: ""}, config.Timeout)
		errors = append(errors, request.Errors...)

		requests = append(requests, &request)
		if grpcLib.AnalyzeResponse(&request) {
			attempt.Finding = true
		}
	}

	attempt.Requests = requests
	return &attempt, errors
}

func (grpcLib *GrpcLibrary) AnalyzeResponse(response *common.RequestInfo) bool {
	if response == nil || response.ResponseHeaders == nil {
		return false
	}

	// Check for gRPC-specific headers
	for key, value := range response.ResponseHeaders {
		keyLower := strings.ToLower(key)
		valueLower := strings.ToLower(value)

		// Content-Type must indicate gRPC
		if keyLower == "content-type" && strings.Contains(valueLower, "application/grpc") {
			return true
		}

		// Look for gRPC-specific headers
		if keyLower == "grpc-status" || keyLower == "grpc-message" {
			return true
		}
	}

	return false
}
