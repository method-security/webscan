package apiapplication

import (
	webscan "github.com/Method-Security/webscan/generated/go/app"
	common "github.com/Method-Security/webscan/generated/go/common"
)

type GrpcLibrary struct{}

func (grpcLib *GrpcLibrary) Name() *webscan.AppFingerprintResourceModule {
	return webscan.NewAppFingerprintResourceModuleFromApiApplicationModule(webscan.ApiApplicationModuleGrpc)
}

func (grpcLib *GrpcLibrary) Paths() []string {
	paths := []string{
		"/grpc.health.v1.Health/Check",
		"/grpc.health.v1alpha.Health/Check",
		"/grpc.health.v1beta.Health/Check",
		"/grpc.reflection.v1alpha.ServerReflectionInfo",
		"/grpc.reflection.v1.ServerReflectionInfo",
		"/grpc.reflection.v1beta.ServerReflectionInfo",
		"/auth.Authentication/Login",
		"/user.UserService/GetUser",
	}
	return paths
}

func (grpcLib *GrpcLibrary) RequestParams() (common.HttpMethod, common.RequestParams) {
	headers := map[string]string{
		"Content-Type": "application/grpc",
	}
	return common.HttpMethodPost, common.RequestParams{HeaderParams: headers}
}

func (grpcLib *GrpcLibrary) HeaderIndicators() map[string][]string {
	return map[string][]string{
		"grpc-status":  {""},
		"grpc-message": {""},
		"content-type": {"application/grpc"},
	}
}

func (grpcLib *GrpcLibrary) BodyIndicators() []string {
	return []string{}
}
