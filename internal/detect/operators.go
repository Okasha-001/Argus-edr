package detect

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/argus-edr/argus/internal/model"
)

type predicate = func(*model.Event) bool

// compileLeaf turns a field/op/value triple into a predicate, validating the
// field name and operator and precompiling regexes, CIDRs and value lists so
// the hot path does no parsing.
func compileLeaf(field, op string, value any) (predicate, error) {
	if field == "" {
		return nil, fmt.Errorf("leaf condition has no field")
	}
	if !model.KnownField(field) {
		return nil, fmt.Errorf("unknown field %q", field)
	}

	switch op {
	case "exists":
		return func(e *model.Event) bool { _, ok := e.Field(field); return ok }, nil
	case "eq":
		return equality(field, value, false), nil
	case "ne":
		return equality(field, value, true), nil
	case "in":
		return membership(field, value, false)
	case "not_in":
		return membership(field, value, true)
	case "contains", "startswith", "endswith":
		return stringMatch(field, op, value)
	case "regex":
		return regexMatch(field, value)
	case "gt", "lt", "ge", "le":
		return numberCompare(field, op, value)
	case "cidr":
		return cidrMatch(field, value)
	default:
		return nil, fmt.Errorf("unknown operator %q", op)
	}
}

func equality(field string, want any, negate bool) predicate {
	return func(e *model.Event) bool {
		actual, ok := e.Field(field)
		if !ok {
			return negate
		}
		return valuesEqual(actual, want) != negate
	}
}

func membership(field string, value any, negate bool) (predicate, error) {
	list, ok := value.([]any)
	if !ok {
		return nil, fmt.Errorf("operator in/not_in needs a list value, got %T", value)
	}
	return func(e *model.Event) bool {
		actual, ok := e.Field(field)
		if !ok {
			return negate
		}
		for _, want := range list {
			if valuesEqual(actual, want) {
				return !negate
			}
		}
		return negate
	}, nil
}

func stringMatch(field, op string, value any) (predicate, error) {
	want := toString(value)
	return func(e *model.Event) bool {
		actual, ok := stringField(e, field)
		if !ok {
			return false
		}
		switch op {
		case "contains":
			return strings.Contains(actual, want)
		case "startswith":
			return strings.HasPrefix(actual, want)
		default:
			return strings.HasSuffix(actual, want)
		}
	}, nil
}

func regexMatch(field string, value any) (predicate, error) {
	expr, err := regexp.Compile(toString(value))
	if err != nil {
		return nil, fmt.Errorf("invalid regex %q: %w", value, err)
	}
	return func(e *model.Event) bool {
		actual, ok := stringField(e, field)
		return ok && expr.MatchString(actual)
	}, nil
}

func numberCompare(field, op string, value any) (predicate, error) {
	want, ok := toInt64(value)
	if !ok {
		return nil, fmt.Errorf("operator %s needs a numeric value, got %T", op, value)
	}
	return func(e *model.Event) bool {
		actual, ok := e.Field(field)
		if !ok {
			return false
		}
		n, ok := actual.(int64)
		if !ok {
			return false
		}
		switch op {
		case "gt":
			return n > want
		case "lt":
			return n < want
		case "ge":
			return n >= want
		default:
			return n <= want
		}
	}, nil
}

func cidrMatch(field string, value any) (predicate, error) {
	_, network, err := net.ParseCIDR(toString(value))
	if err != nil {
		return nil, fmt.Errorf("invalid cidr %q: %w", value, err)
	}
	return func(e *model.Event) bool {
		actual, ok := stringField(e, field)
		if !ok {
			return false
		}
		ip := net.ParseIP(actual)
		return ip != nil && network.Contains(ip)
	}, nil
}

func stringField(e *model.Event, field string) (string, bool) {
	actual, ok := e.Field(field)
	if !ok {
		return "", false
	}
	s, ok := actual.(string)
	return s, ok
}

func valuesEqual(actual, want any) bool {
	switch a := actual.(type) {
	case string:
		return a == toString(want)
	case bool:
		w, ok := toBool(want)
		return ok && a == w
	case int64:
		w, ok := toInt64(want)
		return ok && a == w
	default:
		return fmt.Sprint(actual) == fmt.Sprint(want)
	}
}

func toString(value any) string {
	if s, ok := value.(string); ok {
		return s
	}
	return fmt.Sprint(value)
}

func toBool(value any) (bool, bool) {
	switch v := value.(type) {
	case bool:
		return v, true
	case string:
		b, err := strconv.ParseBool(v)
		return b, err == nil
	default:
		return false, false
	}
}

func toInt64(value any) (int64, bool) {
	switch v := value.(type) {
	case int:
		return int64(v), true
	case int64:
		return v, true
	case uint32:
		return int64(v), true
	case float64:
		return int64(v), true
	case string:
		n, err := strconv.ParseInt(v, 10, 64)
		return n, err == nil
	default:
		return 0, false
	}
}
