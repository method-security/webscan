package govaluate

import (
	"errors"
	"fmt"
	"regexp"
	"time"
)

/*
	Returns a string representing this expression as if it were written in SQL.
	This function assumes that all parameters exist within the same table, and that the table essentially represents
	a serialized object of some sort (e.g., hibernate).
	If your data model is more normalized, you may need to consider iterating through each actual token given by `Tokens()`
	to create your query.

	Boolean values are considered to be "1" for true, "0" for false.

	Times are formatted according to this.QueryDateFormat.
*/
func (this EvaluableExpression) ToSQLQuery() (string, error) {

	var stream *tokenStream
	var transactions *expressionOutputStream
	var transaction string
	var err error

	stream = newTokenStream(this.tokens)
	transactions = new(expressionOutputStream)

	for stream.hasNext() {

		transaction, err = this.findNextSQLString(stream, transactions)
		if err != nil {
			return "", err
		}

		transactions.add(transaction)
	}

	return transactions.createString(" "), nil
}

func (this EvaluableExpression) findNextSQLString(stream *tokenStream, transactions *expressionOutputStream) (string, error) {

	var token ExpressionToken
	var ret string

	if !stream.hasNext() {
		return "", errors.New("Unexpected end of SQL token stream")
	}

	token = stream.next()

	switch token.Kind {

	case STRING:
		ret = fmt.Sprintf("'%v'", token.Value)
	case PATTERN:
		pattern, ok := token.Value.(*regexp.Regexp)
		if !ok || pattern == nil {
			return "", fmt.Errorf("Unable to convert PATTERN token with value type %T to SQL", token.Value)
		}
		ret = fmt.Sprintf("'%s'", pattern.String())
	case TIME:
		tokenTime, ok := token.Value.(time.Time)
		if !ok {
			return "", fmt.Errorf("Unable to convert TIME token with value type %T to SQL", token.Value)
		}
		ret = fmt.Sprintf("'%s'", tokenTime.Format(this.QueryDateFormat))

	case LOGICALOP:
		op, ok := token.Value.(string)
		if !ok {
			return "", fmt.Errorf("Unable to convert LOGICALOP token with value type %T to SQL", token.Value)
		}
		switch logicalSymbols[op] {

		case AND:
			ret = "AND"
		case OR:
			ret = "OR"
		default:
			return "", fmt.Errorf("Unrecognized logical operator '%s'", op)
		}

	case BOOLEAN:
		boolVal, ok := token.Value.(bool)
		if !ok {
			return "", fmt.Errorf("Unable to convert BOOLEAN token with value type %T to SQL", token.Value)
		}
		if boolVal {
			ret = "1"
		} else {
			ret = "0"
		}

	case VARIABLE:
		name, ok := token.Value.(string)
		if !ok {
			return "", fmt.Errorf("Unable to convert VARIABLE token with value type %T to SQL", token.Value)
		}
		ret = fmt.Sprintf("[%s]", name)

	case NUMERIC:
		num, ok := token.Value.(float64)
		if !ok {
			return "", fmt.Errorf("Unable to convert NUMERIC token with value type %T to SQL", token.Value)
		}
		ret = fmt.Sprintf("%g", num)

	case COMPARATOR:
		op, ok := token.Value.(string)
		if !ok {
			return "", fmt.Errorf("Unable to convert COMPARATOR token with value type %T to SQL", token.Value)
		}
		switch comparatorSymbols[op] {

		case EQ:
			ret = "="
		case NEQ:
			ret = "<>"
		case REQ:
			ret = "RLIKE"
		case NREQ:
			ret = "NOT RLIKE"
		default:
			ret = op
		}

	case TERNARY:
		op, ok := token.Value.(string)
		if !ok {
			return "", fmt.Errorf("Unable to convert TERNARY token with value type %T to SQL", token.Value)
		}

		switch ternarySymbols[op] {

		case COALESCE:

			left, err := transactions.rollback()
			if err != nil {
				return "", err
			}
			right, err := this.findNextSQLString(stream, transactions)
			if err != nil {
				return "", err
			}

			ret = fmt.Sprintf("COALESCE(%v, %v)", left, right)
		case TERNARY_TRUE:
			fallthrough
		case TERNARY_FALSE:
			return "", errors.New("Ternary operators are unsupported in SQL output")
		default:
			return "", fmt.Errorf("Unrecognized ternary operator '%s'", op)
		}
	case PREFIX:
		op, ok := token.Value.(string)
		if !ok {
			return "", fmt.Errorf("Unable to convert PREFIX token with value type %T to SQL", token.Value)
		}
		switch prefixSymbols[op] {

		case INVERT:
			ret = "NOT"
		default:

			right, err := this.findNextSQLString(stream, transactions)
			if err != nil {
				return "", err
			}

			ret = fmt.Sprintf("%s%s", op, right)
		}
	case MODIFIER:
		op, ok := token.Value.(string)
		if !ok {
			return "", fmt.Errorf("Unable to convert MODIFIER token with value type %T to SQL", token.Value)
		}

		switch modifierSymbols[op] {

		case EXPONENT:

			left, err := transactions.rollback()
			if err != nil {
				return "", err
			}
			right, err := this.findNextSQLString(stream, transactions)
			if err != nil {
				return "", err
			}

			ret = fmt.Sprintf("POW(%s, %s)", left, right)
		case MODULUS:

			left, err := transactions.rollback()
			if err != nil {
				return "", err
			}
			right, err := this.findNextSQLString(stream, transactions)
			if err != nil {
				return "", err
			}

			ret = fmt.Sprintf("MOD(%s, %s)", left, right)
		default:
			ret = op
		}
	case CLAUSE:
		ret = "("
	case CLAUSE_CLOSE:
		ret = ")"
	case SEPARATOR:
		ret = ","

	default:
		errorMsg := fmt.Sprintf("Unrecognized query token '%s' of kind '%s'", token.Value, token.Kind)
		return "", errors.New(errorMsg)
	}

	return ret, nil
}
