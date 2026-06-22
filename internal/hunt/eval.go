package hunt

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/argus-edr/argus/internal/model"
)

// expr is a boolean predicate over an event — the compiled form of an ARQL
// `where` clause. It is evaluated in userspace against the same rule-visible
// fields the detection engine sees (model.Event.Field), so a hunt and a rule
// agree on what a field means. toCond projects it back to a detection-rule
// condition tree so a proven hunt becomes a rule (see torule.go).
type expr interface {
	eval(event *model.Event) bool
	toCond() *ruleCond
}

type andExpr struct{ left, right expr }
type orExpr struct{ left, right expr }
type notExpr struct{ inner expr }

func (e andExpr) eval(ev *model.Event) bool { return e.left.eval(ev) && e.right.eval(ev) }
func (e orExpr) eval(ev *model.Event) bool  { return e.left.eval(ev) || e.right.eval(ev) }
func (e notExpr) eval(ev *model.Event) bool { return !e.inner.eval(ev) }

// value is a parsed literal: either a number or a string.
type value struct {
	str   string
	num   float64
	isNum bool
}

func (v value) String() string {
	if v.isNum {
		return strconv.FormatFloat(v.num, 'g', -1, 64)
	}
	return v.str
}

// comparison tests one field against a value (or list of values for `in`).
type comparison struct {
	field  string
	op     string
	value  value
	values []value
	re     *regexp.Regexp // compiled at parse time for the =~ operator
}

func (c comparison) eval(ev *model.Event) bool {
	raw, ok := ev.Field(c.field)
	if !ok {
		return false // an absent field never matches, including !=
	}
	switch c.op {
	case "==":
		return valueEquals(raw, c.value)
	case "!=":
		return !valueEquals(raw, c.value)
	case "contains":
		return strings.Contains(toString(raw), c.value.str)
	case "startswith":
		return strings.HasPrefix(toString(raw), c.value.str)
	case "endswith":
		return strings.HasSuffix(toString(raw), c.value.str)
	case "=~":
		return c.re != nil && c.re.MatchString(toString(raw))
	case "in":
		for _, v := range c.values {
			if valueEquals(raw, v) {
				return true
			}
		}
		return false
	case ">", "<", ">=", "<=":
		return numericCompare(raw, c.op, c.value)
	default:
		return false
	}
}

func valueEquals(raw any, v value) bool {
	switch typed := raw.(type) {
	case int64:
		num, ok := v.asNumber()
		return ok && float64(typed) == num
	case bool:
		return v.str == strconv.FormatBool(typed)
	case string:
		return typed == v.String()
	default:
		return false
	}
}

func numericCompare(raw any, op string, v value) bool {
	left, ok := toNumber(raw)
	if !ok {
		return false
	}
	right, ok := v.asNumber()
	if !ok {
		return false
	}
	switch op {
	case ">":
		return left > right
	case "<":
		return left < right
	case ">=":
		return left >= right
	case "<=":
		return left <= right
	default:
		return false
	}
}

func (v value) asNumber() (float64, bool) {
	if v.isNum {
		return v.num, true
	}
	num, err := strconv.ParseFloat(v.str, 64)
	return num, err == nil
}

func toString(raw any) string {
	switch typed := raw.(type) {
	case string:
		return typed
	case int64:
		return strconv.FormatInt(typed, 10)
	case bool:
		return strconv.FormatBool(typed)
	default:
		return fmt.Sprint(raw)
	}
}

func toNumber(raw any) (float64, bool) {
	switch typed := raw.(type) {
	case int64:
		return float64(typed), true
	case string:
		num, err := strconv.ParseFloat(typed, 64)
		return num, err == nil
	default:
		return 0, false
	}
}
