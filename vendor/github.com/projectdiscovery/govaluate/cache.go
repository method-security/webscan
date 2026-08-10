//go:build go1.24 && cache

package govaluate

import (
	"reflect"
	"sync"
	"weak"
)

var (
	paramMap = sync.Map{}

	constMap = sync.Map{}
)

func getParameterStage(name string) (*evaluationStage, error) {
	stage, ok := getParamFromMap(name)
	if ok {
		return stage, nil
	}

	operator := makeParameterStage(name)
	ret := &evaluationStage{
		operator: operator,
	}
	ret.finalize()
	storeVal := weak.Make(ret)
	paramMap.Store(name, storeVal)
	return ret, nil
}

func getParamFromMap(name string) (*evaluationStage, bool) {
	stage, ok := paramMap.Load(name)
	if ok {
		ptr, ok := stage.(weak.Pointer[evaluationStage])
		if ok {
			ret := ptr.Value()
			if ret != nil {
				return ret, true
			}
			paramMap.Delete(name)
		}
	}
	return nil, false
}

func getConstantStage(value any) (*evaluationStage, error) {
	cacheable := canCacheConstant(value)
	if cacheable {
		if stage, ok := getConstantFromMap(value); ok {
			return stage, nil
		}
	}

	operator := makeLiteralStage(value)
	ret := &evaluationStage{
		symbol:   LITERAL,
		operator: operator,
	}
	ret.finalize()
	if cacheable {
		storeVal := weak.Make(ret)
		constMap.Store(value, storeVal)
	}
	return ret, nil
}

func canCacheConstant(value any) bool {
	if value == nil {
		return true
	}
	switch reflect.TypeOf(value).Kind() {
	case reflect.Slice, reflect.Map, reflect.Func:
		return false
	default:
		return true
	}
}

func getConstantFromMap(value any) (*evaluationStage, bool) {
	stage, ok := constMap.Load(value)
	if ok {
		ptr, ok := stage.(weak.Pointer[evaluationStage])
		if ok {
			ret := ptr.Value()
			if ret != nil {
				return ret, true
			}
			constMap.Delete(value)
		}
	}
	return nil, false
}
