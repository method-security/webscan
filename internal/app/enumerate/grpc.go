package enumerate

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"time"

	webscan "github.com/Method-Security/webscan/generated/go/app/enumerate"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/reflection/grpc_reflection_v1alpha"
	"google.golang.org/protobuf/proto"
	descriptorpb "google.golang.org/protobuf/types/descriptorpb"
)

// PerformAppEnumerateGrpc performs a gRPC scan against a target URL and returns the report.
func PerformAppEnumerateGrpc(ctx context.Context, target string) webscan.RoutesReport {
	report := webscan.RoutesReport{Target: target, BaseEndpointUrl: target, AppType: webscan.ApiTypeGrpc}

	conn, err := connectToGRPCServer(target)
	if err != nil {
		report.Errors = append(report.Errors, err.Error())
		return report
	}
	defer closeConnection(conn)

	stream, err := createReflectionClient(ctx, conn)
	if err != nil {
		report.Errors = append(report.Errors, err.Error())
		return report
	}

	services, err := requestAndReceiveServices(stream)
	if err != nil {
		report.Errors = append(report.Errors, err.Error())
		return report
	}

	rawDescriptors, err := processServices(stream, services, &report)
	if err != nil {
		report.Errors = append(report.Errors, err.Error())
		return report
	}

	if err := encodeRawDescriptors(rawDescriptors, &report); err != nil {
		report.Errors = append(report.Errors, err.Error())
		return report
	}

	return report
}

func connectToGRPCServer(target string) (*grpc.ClientConn, error) {
	conn, err := grpc.Dial(target, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock(), grpc.WithTimeout(20*time.Second))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to gRPC server: %v", err)
	}
	return conn, nil
}

func closeConnection(conn *grpc.ClientConn) {
	if err := conn.Close(); err != nil {
		log.Println("Error closing connection:", err)
	}
}

func createReflectionClient(ctx context.Context, conn *grpc.ClientConn) (grpc_reflection_v1alpha.ServerReflection_ServerReflectionInfoClient, error) {
	client := grpc_reflection_v1alpha.NewServerReflectionClient(conn)
	stream, err := client.ServerReflectionInfo(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create reflection client: %v", err)
	}
	return stream, nil
}

func requestAndReceiveServices(stream grpc_reflection_v1alpha.ServerReflection_ServerReflectionInfoClient) ([]*grpc_reflection_v1alpha.ServiceResponse, error) {
	if err := stream.Send(&grpc_reflection_v1alpha.ServerReflectionRequest{
		MessageRequest: &grpc_reflection_v1alpha.ServerReflectionRequest_ListServices{
			ListServices: "*",
		},
	}); err != nil {
		return nil, fmt.Errorf("failed to request list of services: %v", err)
	}

	resp, err := stream.Recv()
	if err != nil {
		return nil, fmt.Errorf("failed to receive list of services: %v", err)
	}

	return resp.GetListServicesResponse().Service, nil
}

func processServices(stream grpc_reflection_v1alpha.ServerReflection_ServerReflectionInfoClient, services []*grpc_reflection_v1alpha.ServiceResponse, report *webscan.RoutesReport) ([]*descriptorpb.FileDescriptorProto, error) {
	var rawDescriptors []*descriptorpb.FileDescriptorProto

	for _, service := range services {
		serviceName := service.Name

		if err := requestFileDescriptor(stream, serviceName); err != nil {
			report.Errors = append(report.Errors, err.Error())
			return nil, err
		}

		fileDescriptorBytes, err := receiveFileDescriptor(stream, serviceName)
		if err != nil {
			report.Errors = append(report.Errors, err.Error())
			return nil, err
		}

		if err := unmarshalFileDescriptors(fileDescriptorBytes, &rawDescriptors, report); err != nil {
			report.Errors = append(report.Errors, err.Error())
			return nil, err
		}
	}

	return rawDescriptors, nil
}

func requestFileDescriptor(stream grpc_reflection_v1alpha.ServerReflection_ServerReflectionInfoClient, serviceName string) error {
	return stream.Send(&grpc_reflection_v1alpha.ServerReflectionRequest{
		MessageRequest: &grpc_reflection_v1alpha.ServerReflectionRequest_FileContainingSymbol{
			FileContainingSymbol: serviceName,
		},
	})
}

func receiveFileDescriptor(stream grpc_reflection_v1alpha.ServerReflection_ServerReflectionInfoClient, serviceName string) ([][]byte, error) {
	resp, err := stream.Recv()
	if err != nil {
		return nil, fmt.Errorf("failed to receive file descriptor for service %s: %v", serviceName, err)
	}
	return resp.GetFileDescriptorResponse().FileDescriptorProto, nil
}

func unmarshalFileDescriptors(fileDescriptorBytes [][]byte, rawDescriptors *[]*descriptorpb.FileDescriptorProto, report *webscan.RoutesReport) error {
	for _, fdBytes := range fileDescriptorBytes {
		var fileDesc descriptorpb.FileDescriptorProto
		if err := proto.Unmarshal(fdBytes, &fileDesc); err != nil {
			return fmt.Errorf("failed to unmarshal file descriptor: %v", err)
		}
		*rawDescriptors = append(*rawDescriptors, &fileDesc)

		extractMethods(&fileDesc, report)
	}
	return nil
}

func extractMethods(fileDesc *descriptorpb.FileDescriptorProto, report *webscan.RoutesReport) {
	for _, service := range fileDesc.Service {
		for _, method := range service.Method {
			queryParams := extractFields(fileDesc, method.GetInputType())
			route := webscan.Route{
				Path:        fmt.Sprintf("/%s/%s", service.GetName(), method.GetName()),
				Method:      "POST",
				Security:    nil,
				QueryParams: queryParams,
				Type:        webscan.ApiTypeGrpc,
				Description: method.GetName(),
			}
			report.Routes = append(report.Routes, &route)
		}
	}
}

func encodeRawDescriptors(rawDescriptors []*descriptorpb.FileDescriptorProto, report *webscan.RoutesReport) error {
	rawData, err := proto.Marshal(&descriptorpb.FileDescriptorSet{File: rawDescriptors})
	if err != nil {
		return fmt.Errorf("failed to marshal raw descriptors: %v", err)
	}
	report.Raw = base64.StdEncoding.EncodeToString(rawData)
	return nil
}

// extracts the fields of a given message type from the file descriptor.
func extractFields(fileDesc *descriptorpb.FileDescriptorProto, messageType string) []string {
	var fields []string
	for _, msg := range fileDesc.MessageType {
		if fmt.Sprintf(".%s.%s", fileDesc.GetPackage(), msg.GetName()) == messageType {
			for _, field := range msg.Field {
				fields = append(fields, field.GetName())
			}
			break
		}
	}
	return fields
}
