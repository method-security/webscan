package apiapplication

import (
	"testing"

	schemayaml "github.com/pb33f/go-yaml"
	base "github.com/pb33f/libopenapi/datamodel/high/base"
	v2 "github.com/pb33f/libopenapi/datamodel/high/v2"
	v3 "github.com/pb33f/libopenapi/datamodel/high/v3"
)

func scalarNode(value string) *schemayaml.Node {
	return &schemayaml.Node{Kind: schemayaml.ScalarNode, Tag: "!!str", Value: value}
}

func TestGetPathParamExamplesV2UsesExplicitDefaultsAndEnums(t *testing.T) {
	examples := getPathParamExamplesV2(nil, []*v2.Parameter{{
		Name:    "petId",
		In:      "path",
		Default: scalarNode("1042"),
		Enum:    []*schemayaml.Node{scalarNode("1042"), scalarNode("3517")},
	}})

	got := examples["petId"]
	if len(got) != 2 || got[0] != "1042" || got[1] != "3517" {
		t.Fatalf("expected deduplicated explicit examples, got %v", got)
	}
}

func TestGetPathParamExamplesV3UsesParameterExample(t *testing.T) {
	examples := getPathParamExamplesV3(nil, []*v3.Parameter{{
		Name:    "orderId",
		In:      "path",
		Example: scalarNode("12"),
	}})

	got := examples["orderId"]
	if len(got) != 1 || got[0] != "12" {
		t.Fatalf("expected the parameter example, got %v", got)
	}
}

func TestGetPathParamExamplesV3IgnoresNonPathAndNonScalarValues(t *testing.T) {
	examples := getPathParamExamplesV3(nil, []*v3.Parameter{
		{
			Name:    "orderId",
			In:      "query",
			Example: scalarNode("12"),
		},
		{
			Name: "itemId",
			In:   "path",
			Example: &schemayaml.Node{
				Kind: schemayaml.MappingNode,
			},
		},
	})

	if len(examples) != 0 {
		t.Fatalf("expected only explicit scalar path examples to be emitted, got %v", examples)
	}
}

func TestGetQueryParamsV2IncludesStructuredExamples(t *testing.T) {
	params := getQueryParamsV2([]*v2.Parameter{{
		Name:    "status",
		In:      "query",
		Default: scalarNode("available"),
		Enum:    []*schemayaml.Node{scalarNode("available"), scalarNode("pending")},
	}})

	if len(params) != 1 {
		t.Fatalf("expected one query param, got %v", params)
	}
	if params[0].Name != "status" || len(params[0].ExampleValues) != 2 || params[0].ExampleValues[0] != "available" || params[0].ExampleValues[1] != "pending" {
		t.Fatalf("expected structured query examples, got %v", params[0])
	}
}

func TestGetQueryParamsV3IncludesStructuredExamples(t *testing.T) {
	params := getQueryParamsV3([]*v3.Parameter{{Name: "filter", In: "query", Example: scalarNode("active")}})

	if len(params) != 1 || params[0].Name != "filter" || len(params[0].ExampleValues) != 1 || params[0].ExampleValues[0] != "active" {
		t.Fatalf("expected structured query examples, got %v", params)
	}
}

func TestGetPathParamsV3IncludesStructuredExamplesAndTemplateOnlyParams(t *testing.T) {
	params := getPathParamsV3(nil, []*v3.Parameter{{
		Name:    "orderId",
		In:      "path",
		Example: scalarNode("12"),
	}}, "/orders/{orderId}/items/{itemId}")

	if len(params) != 2 {
		t.Fatalf("expected declared and template-only params, got %v", params)
	}
	if params[0].Name != "orderId" || len(params[0].ExampleValues) != 1 || params[0].ExampleValues[0] != "12" {
		t.Fatalf("expected structured orderId examples, got %v", params[0])
	}
	if params[1].Name != "itemId" || params[1].ExampleValues != nil {
		t.Fatalf("expected template-only itemId without examples, got %v", params[1])
	}
}

func TestAppendSchemaExampleValuesUsesExplicitSchemaValues(t *testing.T) {
	values := appendSchemaExampleValues(nil, &base.Schema{
		Example: scalarNode("dog"),
		Default: scalarNode("cat"),
		Enum:    []*schemayaml.Node{scalarNode("dog"), scalarNode("bird")},
	})

	if len(values) != 3 || values[0] != "dog" || values[1] != "cat" || values[2] != "bird" {
		t.Fatalf("expected ordered schema examples, got %v", values)
	}
}

func TestEffectivePathParamsV3LetsOperationOverridePathItem(t *testing.T) {
	params := effectivePathParamsV3(
		[]*v3.Parameter{{Name: "id", In: "path", Example: scalarNode("path-item")}},
		[]*v3.Parameter{{Name: "id", In: "path", Example: scalarNode("operation")}},
	)

	if len(params) != 1 || params[0].Example == nil || params[0].Example.Value != "operation" {
		t.Fatalf("expected the operation parameter to override the path item, got %v", params)
	}
}
