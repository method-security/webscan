//go:build !go1.24 || !cache

package govaluate

func getParameterStage(name string) (*evaluationStage, error) {
	operator := makeParameterStage(name)
	s := &evaluationStage{
		operator: operator,
	}
	s.finalize()
	return s, nil
}

func getConstantStage(value interface{}) (*evaluationStage, error) {
	operator := makeLiteralStage(value)
	s := &evaluationStage{
		symbol:   LITERAL,
		operator: operator,
	}
	s.finalize()
	return s, nil
}
