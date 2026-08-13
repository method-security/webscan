package govaluate

import (
	"errors"
	"fmt"
	"time"
)

var stageSymbolMap = map[OperatorSymbol]evaluationOperator{
	EQ:             equalStage,
	NEQ:            notEqualStage,
	GT:             gtStage,
	LT:             ltStage,
	GTE:            gteStage,
	LTE:            lteStage,
	REQ:            regexStage,
	NREQ:           notRegexStage,
	AND:            andStage,
	OR:             orStage,
	IN:             inStage,
	BITWISE_OR:     bitwiseOrStage,
	BITWISE_AND:    bitwiseAndStage,
	BITWISE_XOR:    bitwiseXORStage,
	BITWISE_LSHIFT: leftShiftStage,
	BITWISE_RSHIFT: rightShiftStage,
	PLUS:           addStage,
	MINUS:          subtractStage,
	MULTIPLY:       multiplyStage,
	DIVIDE:         divideStage,
	MODULUS:        modulusStage,
	EXPONENT:       exponentStage,
	NEGATE:         negateStage,
	INVERT:         invertStage,
	BITWISE_NOT:    bitwiseNotStage,
	TERNARY_TRUE:   ternaryIfStage,
	TERNARY_FALSE:  ternaryElseStage,
	COALESCE:       ternaryElseStage,
	SEPARATE:       separatorStage,
}

/*
	A "precedent" is a function which will recursively parse new evaluateionStages from a given stream of tokens.
	It's called a `precedent` because it is expected to handle exactly what precedence of operator,
	and defer to other `precedent`s for other operators.
*/
type precedent func(stream *tokenStream) (*evaluationStage, error)

/*
	A convenience function for specifying the behavior of a `precedent`.
	Most `precedent` functions can be described by the same function, just with different type checks, symbols, and error formats.
	This struct is passed to `makePrecedentFromPlanner` to create a `precedent` function.
*/
type precedencePlanner struct {
	validSymbols map[string]OperatorSymbol
	validKinds   []TokenKind

	typeErrorFormat string

	next      precedent
	nextRight precedent
}

var planPrefix precedent
var planExponential precedent
var planMultiplicative precedent
var planAdditive precedent
var planBitwise precedent
var planShift precedent
var planComparator precedent
var planLogicalAnd precedent
var planLogicalOr precedent
var planTernary precedent
var planSeparator precedent

func init() {

	// all these stages can use the same code (in `planPrecedenceLevel`) to execute,
	// they simply need different type checks, symbols, and recursive precedents.
	// While not all precedent phases are listed here, most can be represented this way.
	planPrefix = makePrecedentFromPlanner(&precedencePlanner{
		validSymbols:    prefixSymbols,
		validKinds:      []TokenKind{PREFIX},
		typeErrorFormat: prefixErrorFormat,
		nextRight:       planFunction,
	})
	planExponential = makePrecedentFromPlanner(&precedencePlanner{
		validSymbols:    exponentialSymbolsS,
		validKinds:      []TokenKind{MODIFIER},
		typeErrorFormat: modifierErrorFormat,
		next:            planFunction,
	})
	planMultiplicative = makePrecedentFromPlanner(&precedencePlanner{
		validSymbols:    multiplicativeSymbols,
		validKinds:      []TokenKind{MODIFIER},
		typeErrorFormat: modifierErrorFormat,
		next:            planExponential,
	})
	planAdditive = makePrecedentFromPlanner(&precedencePlanner{
		validSymbols:    additiveSymbols,
		validKinds:      []TokenKind{MODIFIER},
		typeErrorFormat: modifierErrorFormat,
		next:            planMultiplicative,
	})
	planShift = makePrecedentFromPlanner(&precedencePlanner{
		validSymbols:    bitwiseShiftSymbols,
		validKinds:      []TokenKind{MODIFIER},
		typeErrorFormat: modifierErrorFormat,
		next:            planAdditive,
	})
	planBitwise = makePrecedentFromPlanner(&precedencePlanner{
		validSymbols:    bitwiseSymbols,
		validKinds:      []TokenKind{MODIFIER},
		typeErrorFormat: modifierErrorFormat,
		next:            planShift,
	})
	planComparator = makePrecedentFromPlanner(&precedencePlanner{
		validSymbols:    comparatorSymbols,
		validKinds:      []TokenKind{COMPARATOR},
		typeErrorFormat: comparatorErrorFormat,
		next:            planBitwise,
	})
	planLogicalAnd = makePrecedentFromPlanner(&precedencePlanner{
		validSymbols:    map[string]OperatorSymbol{"&&": AND},
		validKinds:      []TokenKind{LOGICALOP},
		typeErrorFormat: logicalErrorFormat,
		next:            planComparator,
	})
	planLogicalOr = makePrecedentFromPlanner(&precedencePlanner{
		validSymbols:    map[string]OperatorSymbol{"||": OR},
		validKinds:      []TokenKind{LOGICALOP},
		typeErrorFormat: logicalErrorFormat,
		next:            planLogicalAnd,
	})
	planTernary = planTernaryExpression
	planSeparator = makePrecedentFromPlanner(&precedencePlanner{
		validSymbols: separatorSymbols,
		validKinds:   []TokenKind{SEPARATOR},
		next:         planTernary,
	})
}

/*
	Given a planner, creates a function which will evaluate a specific precedence level of operators,
	and link it to other `precedent`s which recurse to parse other precedence levels.
*/
func makePrecedentFromPlanner(planner *precedencePlanner) precedent {

	var generated precedent
	var nextRight precedent

	generated = func(stream *tokenStream) (*evaluationStage, error) {
		return planPrecedenceLevel(
			stream,
			planner.typeErrorFormat,
			planner.validSymbols,
			planner.validKinds,
			nextRight,
			planner.next,
		)
	}

	if planner.nextRight != nil {
		nextRight = planner.nextRight
	} else {
		nextRight = generated
	}

	return generated
}

/*
	Creates a `evaluationStageList` object which represents an execution plan (or tree)
	which is used to completely evaluate a set of tokens at evaluation-time.
	The three stages of evaluation can be thought of as parsing strings to tokens, then tokens to a stage list, then evaluation with parameters.
*/
func planStages(tokens []ExpressionToken) (*evaluationStage, error) {

	stream := newTokenStream(tokens)

	stage, err := planTokens(stream)
	if err != nil {
		stream.close()
		return nil, err
	}
	if stream.hasNext() {
		token := stream.next()
		stream.close()
		return nil, fmt.Errorf("unable to plan token kind: '%s', value: '%v'", token.Kind.String(), token.Value)
	}
	stream.close()

	if len(tokens) > 0 && stage == nil {
		return nil, errors.New("unable to plan expression: no evaluation stages produced")
	}

	// while we're now fully-planned, we now need to re-order same-precedence operators.
	// this could probably be avoided with a different planning method
	reorderStages(stage)

	stage = elideLiterals(stage)

	if err := validateEvaluationStages(stage); err != nil {
		return nil, err
	}
	return stage, nil
}

// validateEvaluationStages walks a planned stage tree and rejects any stage
// missing an operator. Empty expressions (nil root) are valid.
func validateEvaluationStages(stage *evaluationStage) error {
	if stage == nil {
		return nil
	}
	if stage.operator == nil {
		return fmt.Errorf("unable to plan expression: nil operator for symbol '%v'", stage.symbol.String())
	}
	if err := validateEvaluationStages(stage.leftStage); err != nil {
		return err
	}
	return validateEvaluationStages(stage.rightStage)
}

func planTokens(stream *tokenStream) (*evaluationStage, error) {

	if !stream.hasNext() {
		return nil, nil
	}

	return planSeparator(stream)
}

// planTernaryExpression parses ternaries and null-coalescing with right associativity
// so that `a ? b : c ? d : e` becomes `a ? b : (c ? d : e)`.
// A trailing ':' is optional (`true ? 10`), matching historical govaluate behavior.
func planTernaryExpression(stream *tokenStream) (*evaluationStage, error) {
	return planTernaryExpressionMode(stream, true)
}

func planTernaryExpressionMode(stream *tokenStream, allowBareColon bool) (*evaluationStage, error) {

	left, err := planLogicalOr(stream)
	if err != nil {
		return nil, err
	}

	for stream.hasNext() {

		token := stream.next()
		if token.Kind != TERNARY || !isString(token.Value) {
			stream.rewind()
			break
		}

		symbol, ok := ternarySymbols[token.Value.(string)]
		if !ok {
			stream.rewind()
			break
		}

		switch symbol {
		case COALESCE:
			// Coalesce binds tighter than ?: so its RHS stops at logical-or;
			// that lets `a ?? b ? c : d` parse as `(a ?? b) ? c : d`.
			right, err := planLogicalOr(stream)
			if err != nil {
				return nil, err
			}
			s := &evaluationStage{
				symbol:          COALESCE,
				leftStage:       left,
				rightStage:      right,
				operator:        stageSymbolMap[COALESCE],
				typeErrorFormat: ternaryErrorFormat,
			}
			s.finalize()
			left = s
			continue

		case TERNARY_TRUE:
			// Middle branch may itself be a ternary, but must not treat the outer
			// ':' as a bare colon operator.
			trueBranch, err := planTernaryExpressionMode(stream, false)
			if err != nil {
				return nil, err
			}

			checks := findTypeChecks(TERNARY_TRUE)
			ifStage := &evaluationStage{
				symbol:          TERNARY_TRUE,
				leftStage:       left,
				rightStage:      trueBranch,
				operator:        stageSymbolMap[TERNARY_TRUE],
				leftTypeCheck:   checks.left,
				rightTypeCheck:  checks.right,
				typeCheck:       checks.combined,
				typeErrorFormat: ternaryErrorFormat,
			}
			ifStage.finalize()

			if stream.hasNext() {
				colon := stream.next()
				if colon.Kind == TERNARY && colon.Value == ":" {
					falseBranch, err := planTernaryExpressionMode(stream, allowBareColon)
					if err != nil {
						return nil, err
					}
					elseStage := &evaluationStage{
						symbol:          TERNARY_FALSE,
						leftStage:       ifStage,
						rightStage:      falseBranch,
						operator:        stageSymbolMap[TERNARY_FALSE],
						typeErrorFormat: ternaryErrorFormat,
					}
					elseStage.finalize()
					return elseStage, nil
				}
				stream.rewind()
			}
			return ifStage, nil

		case TERNARY_FALSE:
			if !allowBareColon {
				stream.rewind()
				return left, nil
			}
			// Allow a lone `:`, matching historical behavior for expressions like `false : 1`.
			right, err := planTernaryExpressionMode(stream, allowBareColon)
			if err != nil {
				return nil, err
			}
			s := &evaluationStage{
				symbol:          TERNARY_FALSE,
				leftStage:       left,
				rightStage:      right,
				operator:        stageSymbolMap[TERNARY_FALSE],
				typeErrorFormat: ternaryErrorFormat,
			}
			s.finalize()
			return s, nil

		default:
			stream.rewind()
			return left, nil
		}
	}

	return left, nil
}

/*
	The most usual method of parsing an evaluation stage for a given precedence.
	Most stages use the same logic
*/
func planPrecedenceLevel(
	stream *tokenStream,
	typeErrorFormat string,
	validSymbols map[string]OperatorSymbol,
	validKinds []TokenKind,
	rightPrecedent precedent,
	leftPrecedent precedent) (*evaluationStage, error) {

	var token ExpressionToken
	var symbol OperatorSymbol
	var leftStage, rightStage *evaluationStage
	var checks typeChecks
	var err error
	var keyFound bool

	if leftPrecedent != nil {

		leftStage, err = leftPrecedent(stream)
		if err != nil {
			return nil, err
		}
	}

	for stream.hasNext() {

		token = stream.next()

		if len(validKinds) > 0 {

			keyFound = false
			for _, kind := range validKinds {
				if kind == token.Kind {
					keyFound = true
					break
				}
			}

			if !keyFound {
				stream.rewind()
				break
			}
		}

		if validSymbols != nil {

			if !isString(token.Value) {
				stream.rewind()
				break
			}

			symbol, keyFound = validSymbols[token.Value.(string)]
			if !keyFound {
				stream.rewind()
				break
			}
		}

		if rightPrecedent != nil {
			rightStage, err = rightPrecedent(stream)
			if err != nil {
				return nil, err
			}
		}

		checks = findTypeChecks(symbol)

		operator := stageSymbolMap[symbol]
		if operator == nil {
			return nil, fmt.Errorf("unable to plan symbol: '%v'", symbol.String())
		}

		errorFormat := typeErrorFormat
		switch symbol {
		case REQ, NREQ:
			errorFormat = regexErrorFormat
		case IN:
			errorFormat = arrayErrorFormat
		}

		s := &evaluationStage{

			symbol:     symbol,
			leftStage:  leftStage,
			rightStage: rightStage,
			operator:   operator,

			leftTypeCheck:   checks.left,
			rightTypeCheck:  checks.right,
			typeCheck:       checks.combined,
			typeErrorFormat: errorFormat,
		}
		s.finalize()
		return s, nil
	}

	return leftStage, nil
}

/*
	A special case where functions need to be of higher precedence than values, and need a special wrapped execution stage operator.
*/
func planFunction(stream *tokenStream) (*evaluationStage, error) {

	var token ExpressionToken
	var rightStage *evaluationStage
	var err error

	token = stream.next()

	if token.Kind != FUNCTION {
		stream.rewind()
		return planAccessor(stream)
	}

	rightStage, err = planAccessor(stream)
	if err != nil {
		return nil, err
	}

	function, ok := token.Value.(ExpressionFunction)
	if !ok || function == nil {
		return nil, fmt.Errorf("unable to plan FUNCTION token with value type %T", token.Value)
	}

	s := &evaluationStage{

		symbol:          FUNCTIONAL,
		rightStage:      rightStage,
		operator:        makeFunctionStage(function),
		typeErrorFormat: "Unable to run function '%v': %v",
	}
	s.finalize()
	return s, nil
}

func planAccessor(stream *tokenStream) (*evaluationStage, error) {

	var token, otherToken ExpressionToken
	var rightStage *evaluationStage
	var err error

	if !stream.hasNext() {
		return nil, nil
	}

	token = stream.next()

	if token.Kind != ACCESSOR {
		stream.rewind()
		return planValue(stream)
	}

	// check if this is meant to be a function or a field.
	// fields have a clause next to them, functions do not.
	// if it's a function, parse the arguments. Otherwise leave the right stage null.
	if stream.hasNext() {

		otherToken = stream.next()
		if otherToken.Kind == CLAUSE {
			// Parse only the tokens inside the parentheses. Starting planTokens on
			// the CLAUSE token itself would climb the full precedence chain and
			// incorrectly absorb trailing operators (e.g. `foo.Bar(1) + 2`).
			if !stream.hasNext() {
				return nil, errors.New("unable to plan expression: missing closing clause")
			}
			if stream.tokens[stream.index].Kind == CLAUSE_CLOSE {
				stream.next()
				rightStage = &evaluationStage{
					symbol:   LITERAL,
					operator: makeLiteralStage(collectedArgs{}),
				}
				rightStage.finalize()
			} else {
				rightStage, err = planTokens(stream)
				if err != nil {
					return nil, err
				}
				if !stream.hasNext() {
					return nil, errors.New("unable to plan expression: missing closing clause")
				}
				closing := stream.next()
				if closing.Kind != CLAUSE_CLOSE {
					return nil, fmt.Errorf("unable to plan expression: expected closing clause, got %s", closing.Kind.String())
				}
				if rightStage == nil {
					rightStage = &evaluationStage{
						symbol:   LITERAL,
						operator: makeLiteralStage(collectedArgs{}),
					}
					rightStage.finalize()
				} else {
					tmp := *rightStage
					tmp.operator = ensureCollectedArgsStage(rightStage.operator)
					rightStage = &tmp
				}
			}
		} else {
			stream.rewind()
		}
	}

	pair, ok := token.Value.([]string)
	if !ok || len(pair) == 0 {
		return nil, fmt.Errorf("unable to plan ACCESSOR token with value type %T", token.Value)
	}

	s := &evaluationStage{

		symbol:          ACCESS,
		rightStage:      rightStage,
		operator:        makeAccessorStage(pair),
		typeErrorFormat: "Unable to access parameter field or method '%v': %v",
	}
	s.finalize()
	return s, nil
}

/*
	A truly special precedence function, this handles all the "lowest-case" errata of the process, including literals, parmeters,
	clauses, and prefixes.
*/
func planValue(stream *tokenStream) (*evaluationStage, error) {

	var token ExpressionToken
	var symbol OperatorSymbol
	var ret *evaluationStage
	var operator evaluationOperator
	var err error

	if !stream.hasNext() {
		return nil, nil
	}

	token = stream.next()

	switch token.Kind {

	case CLAUSE:
		var prev ExpressionToken
		if stream.index > 1 {
			prev = stream.tokens[stream.index-2]
		}

		ret, err = planTokens(stream)
		if err != nil {
			return nil, err
		}

		// clauses with single elements don't trigger SEPARATE stage planner
		// this ensures that when used as part of an "in" comparison, the array requirement passes
		if prev.Kind == COMPARATOR && prev.Value == "in" {
			if ret == nil {
				// empty collection: `in ()`
				ret = &evaluationStage{
					symbol:   LITERAL,
					operator: makeLiteralStage([]interface{}{}),
				}
				ret.finalize()
			} else if ret.symbol != SEPARATE {
				// single value/expression/parameter: wrap as one-element slice
				tmp := *ret
				tmp.operator = ensureSliceStage(ret.operator)
				ret = &tmp
			}
		}

		// empty function argument lists become an explicit zero-arg collection
		// so nil parameter values are not confused with "no arguments".
		if ret == nil && prev.Kind == FUNCTION {
			ret = &evaluationStage{
				symbol:   LITERAL,
				operator: makeLiteralStage(collectedArgs{}),
			}
			ret.finalize()
		}

		// function calls: normalize arg packing (including a single nil arg)
		if ret != nil && prev.Kind == FUNCTION {
			tmp := *ret
			tmp.operator = ensureCollectedArgsStage(ret.operator)
			ret = &tmp
		}

		// advance past the CLAUSE_CLOSE token. We know that it's a CLAUSE_CLOSE, because at parse-time we check for unbalanced parens.
		if !stream.hasNext() {
			return nil, errors.New("unable to plan expression: missing closing clause")
		}
		stream.next()

		// the stage we got represents all the logic contained within the parens
		// but for technical reasons, we need to wrap this stage in a "noop" stage which breaks long chains of precedence.
		// see github #33.
		ret = &evaluationStage{
			rightStage: ret,
			operator:   noopStageRight,
			symbol:     NOOP,
		}
		ret.finalize()

		return ret, nil

	case CLAUSE_CLOSE:

		// when functions have empty params, this will be hit. In this case, we don't have any evaluation stage to do,
		// so we just return nil so that the stage planner continues on its way.
		stream.rewind()
		return nil, nil

	case VARIABLE:
		name, ok := token.Value.(string)
		if !ok {
			return nil, fmt.Errorf("unable to plan VARIABLE token with value type %T", token.Value)
		}
		return getParameterStage(name)

	case NUMERIC:
		num, err := coerceNumericLiteral(token.Value)
		if err != nil {
			return nil, err
		}
		return getConstantStage(num)
	case STRING:
		fallthrough
	case PATTERN:
		fallthrough
	case BOOLEAN:
		if token.Kind == BOOLEAN {
			boolVal, ok := token.Value.(bool)
			if !ok {
				return nil, fmt.Errorf("unable to plan BOOLEAN token with value type %T", token.Value)
			}
			return getConstantStage(boolVal)
		}
		return getConstantStage(token.Value)
	case TIME:
		tokenTime, ok := token.Value.(time.Time)
		if !ok {
			return nil, fmt.Errorf("unable to plan TIME token with value type %T", token.Value)
		}
		return getConstantStage(float64(tokenTime.Unix()))

	case PREFIX:
		stream.rewind()
		return planPrefix(stream)
	}

	if operator == nil {
		errorMsg := fmt.Sprintf("Unable to plan token kind: '%s', value: '%v'", token.Kind.String(), token.Value)
		return nil, errors.New(errorMsg)
	}

	s := &evaluationStage{
		symbol:   symbol,
		operator: operator,
	}
	s.finalize()
	return s, nil
}

func coerceNumericLiteral(value interface{}) (float64, error) {
	switch v := value.(type) {
	case float64:
		return v, nil
	case float32:
		return float64(v), nil
	case int:
		return float64(v), nil
	case int8:
		return float64(v), nil
	case int16:
		return float64(v), nil
	case int32:
		return float64(v), nil
	case int64:
		return float64(v), nil
	case uint:
		return float64(v), nil
	case uint8:
		return float64(v), nil
	case uint16:
		return float64(v), nil
	case uint32:
		return float64(v), nil
	case uint64:
		return float64(v), nil
	default:
		return 0, fmt.Errorf("unable to plan NUMERIC token with value type %T", value)
	}
}

/*
	Convenience function to pass a triplet of typechecks between `findTypeChecks` and `planPrecedenceLevel`.
	Each of these members may be nil, which indicates that type does not matter for that value.
*/
type typeChecks struct {
	left     stageTypeCheck
	right    stageTypeCheck
	combined stageCombinedTypeCheck
}

/*
	Maps a given [symbol] to a set of typechecks to be used during runtime.
*/
func findTypeChecks(symbol OperatorSymbol) typeChecks {

	switch symbol {
	case GT:
		fallthrough
	case LT:
		fallthrough
	case GTE:
		fallthrough
	case LTE:
		return typeChecks{
			combined: comparatorTypeCheck,
		}
	case REQ:
		fallthrough
	case NREQ:
		return typeChecks{
			left:  isString,
			right: isRegexOrString,
		}
	case AND:
		fallthrough
	case OR:
		return typeChecks{
			left:  isBool,
			right: isBool,
		}
	case IN:
		return typeChecks{
			right: isArray,
		}
	case BITWISE_LSHIFT:
		fallthrough
	case BITWISE_RSHIFT:
		fallthrough
	case BITWISE_OR:
		fallthrough
	case BITWISE_AND:
		fallthrough
	case BITWISE_XOR:
		return typeChecks{
			left:  isFloat64,
			right: isFloat64,
		}
	case PLUS:
		return typeChecks{
			combined: additionTypeCheck,
		}
	case MINUS:
		fallthrough
	case MULTIPLY:
		fallthrough
	case DIVIDE:
		fallthrough
	case MODULUS:
		fallthrough
	case EXPONENT:
		return typeChecks{
			left:  isFloat64,
			right: isFloat64,
		}
	case NEGATE:
		return typeChecks{
			right: isFloat64,
		}
	case INVERT:
		return typeChecks{
			right: isBool,
		}
	case BITWISE_NOT:
		return typeChecks{
			right: isFloat64,
		}
	case TERNARY_TRUE:
		return typeChecks{
			left: isBool,
		}

	// unchecked cases
	case EQ:
		fallthrough
	case NEQ:
		return typeChecks{}
	case TERNARY_FALSE:
		fallthrough
	case COALESCE:
		fallthrough
	default:
		return typeChecks{}
	}
}

/*
	During stage planning, stages of equal precedence are parsed such that they'll be evaluated in reverse order.
	For commutative operators like "+" or "-", it's no big deal. But for order-specific operators, it ruins the expected result.
*/
func reorderStages(rootStage *evaluationStage) {

	if rootStage == nil {
		return
	}

	// traverse every rightStage until we find multiples in a row of the same precedence.
	var identicalPrecedences []*evaluationStage
	var currentStage, nextStage *evaluationStage
	var precedence, currentPrecedence operatorPrecedence

	nextStage = rootStage
	precedence = findOperatorPrecedenceForSymbol(rootStage.symbol)

	for nextStage != nil {

		currentStage = nextStage
		nextStage = currentStage.rightStage

		// left depth first, since this entire method only looks for precedences down the right side of the tree
		if currentStage.leftStage != nil {
			reorderStages(currentStage.leftStage)
		}

		currentPrecedence = findOperatorPrecedenceForSymbol(currentStage.symbol)

		// Ternary/coalesce are planned right-associatively; mirroring would undo that.
		switch currentStage.symbol {
		case TERNARY_TRUE, TERNARY_FALSE, COALESCE:
			if len(identicalPrecedences) > 1 {
				mirrorStageSubtree(identicalPrecedences)
			}
			identicalPrecedences = nil
			precedence = currentPrecedence
			continue
		}

		if currentPrecedence == precedence {
			identicalPrecedences = append(identicalPrecedences, currentStage)
			continue
		}

		// precedence break.
		// See how many in a row we had, and reorder if there's more than one.
		if len(identicalPrecedences) > 1 {
			mirrorStageSubtree(identicalPrecedences)
		}

		identicalPrecedences = []*evaluationStage{currentStage}
		precedence = currentPrecedence
	}

	if len(identicalPrecedences) > 1 {
		mirrorStageSubtree(identicalPrecedences)
	}
}

/*
	Performs a "mirror" on a subtree of stages.
	This mirror functionally inverts the order of execution for all members of the [stages] list.
	That list is assumed to be a root-to-leaf (ordered) list of evaluation stages, where each is a right-hand stage of the last.
*/
func mirrorStageSubtree(stages []*evaluationStage) {

	var rootStage, inverseStage, carryStage, frontStage *evaluationStage

	stagesLength := len(stages)

	// reverse all right/left
	for _, frontStage = range stages {

		carryStage = frontStage.rightStage
		frontStage.rightStage = frontStage.leftStage
		frontStage.leftStage = carryStage
	}

	// end left swaps with root right
	rootStage = stages[0]
	frontStage = stages[stagesLength-1]

	carryStage = frontStage.leftStage
	frontStage.leftStage = rootStage.rightStage
	rootStage.rightStage = carryStage

	// for all non-root non-end stages, right is swapped with inverse stage right in list
	for i := 0; i < (stagesLength-2)/2+1; i++ {

		frontStage = stages[i+1]
		inverseStage = stages[stagesLength-i-1]

		carryStage = frontStage.rightStage
		frontStage.rightStage = inverseStage.rightStage
		inverseStage.rightStage = carryStage
	}

	// swap all other information with inverse stages
	for i := 0; i < stagesLength/2; i++ {

		frontStage = stages[i]
		inverseStage = stages[stagesLength-i-1]
		frontStage.swapWith(inverseStage)
	}
}

/*
	Recurses through all operators in the entire tree, eliding operators where both sides are literals.
*/
func elideLiterals(root *evaluationStage) *evaluationStage {

	if root == nil {
		return nil
	}

	if root.leftStage != nil {
		root.leftStage = elideLiterals(root.leftStage)
	}

	if root.rightStage != nil {
		root.rightStage = elideLiterals(root.rightStage)
	}

	return elideStage(root)
}

/*
	Elides a specific stage, if possible.
	Returns the unmodified [root] stage if it cannot or should not be elided.
	Otherwise, returns a new stage representing the condensed value from the elided stages.
*/
func elideStage(root *evaluationStage) *evaluationStage {

	var leftValue, rightValue, result interface{}
	var err error

	// right side must be a non-nil value. Left side must be nil or a value.
	if root.rightStage == nil ||
		root.rightStage.symbol != LITERAL ||
		root.leftStage == nil ||
		root.leftStage.symbol != LITERAL {
		return root
	}

	// don't elide some operators
	switch root.symbol {
	case SEPARATE:
		fallthrough
	case IN:
		return root
	}

	// both sides are values, get their actual values.
	// errors should be near-impossible here. If we encounter them, just abort this optimization.
	leftValue, err = root.leftStage.operator(nil, nil, nil)
	if err != nil {
		return root
	}

	rightValue, err = root.rightStage.operator(nil, nil, nil)
	if err != nil {
		return root
	}

	// typcheck, since the grammar checker is a bit loose with which operator symbols go together.
	err = typeCheck(root.leftTypeCheck, leftValue, root.symbol, root.typeErrorFormat)
	if err != nil {
		return root
	}

	err = typeCheck(root.rightTypeCheck, rightValue, root.symbol, root.typeErrorFormat)
	if err != nil {
		return root
	}

	if root.typeCheck != nil && !root.typeCheck(leftValue, rightValue) {
		return root
	}

	// pre-calculate, and return a new stage representing the result.
	result, err = root.operator(leftValue, rightValue, nil)
	if err != nil {
		return root
	}

	s := &evaluationStage{
		symbol:   LITERAL,
		operator: makeLiteralStage(result),
	}
	s.finalize()
	return s
}
