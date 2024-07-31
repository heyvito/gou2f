package cbor

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"unicode"
)

// 0->u:0x02
// 0->u:3->t:alg

func isNumber(s string) bool {
	if len(s) == 0 {
		return false
	}
	for _, v := range s {
		if !unicode.IsNumber(v) {
			return false
		}
	}
	return true
}

type boreStep struct {
	RequiredType reflect.Kind
	Expr         string
	ExprKind     string
	ExprValue    any
}

func parseBoreExpr(expr string) ([]boreStep, error) {
	steps := strings.Split(expr, "->")
	for i := range steps {
		steps[i] = strings.TrimSpace(steps[i])
	}

	var result []boreStep
	for _, step := range steps {
		if isNumber(step) {
			v, _ := strconv.ParseInt(step, 10, 64)
			result = append(result, boreStep{
				Expr:         step,
				RequiredType: reflect.Array,
				ExprValue:    int(v),
			})
			continue
		}

		comps := strings.SplitN(step, ":", 2)
		kind, name := comps[0], comps[1]
		switch kind {
		case "u":
			var v uint
			if strings.HasPrefix(name, "0x") {
				r, err := strconv.ParseInt(strings.TrimPrefix(name, "0x"), 16, 64)
				if err != nil {
					return nil, fmt.Errorf("failed parsing %s: %w", name, err)
				}
				v = uint(r)
			} else {
				r, err := strconv.ParseInt(name, 10, 64)
				if err != nil {
					return nil, fmt.Errorf("failed parsing %s: %w", name, err)
				}
				v = uint(r)
			}
			result = append(result, boreStep{
				RequiredType: reflect.Map,
				Expr:         name,
				ExprKind:     kind,
				ExprValue:    v,
			})
		case "i":
			var v int
			if strings.HasPrefix(name, "0x") {
				r, err := strconv.ParseInt(strings.TrimPrefix(name, "0x"), 16, 64)
				if err != nil {
					return nil, fmt.Errorf("failed parsing %s: %w", name, err)
				}
				v = int(r)
			} else {
				r, err := strconv.ParseInt(name, 10, 64)
				if err != nil {
					return nil, fmt.Errorf("failed parsing %s: %w", name, err)
				}
				v = int(r)
			}
			result = append(result, boreStep{
				RequiredType: reflect.Map,
				Expr:         name,
				ExprKind:     kind,
				ExprValue:    v,
			})
		case "t":
			result = append(result, boreStep{
				RequiredType: reflect.Map,
				Expr:         name,
				ExprKind:     kind,
				ExprValue:    name,
			})
		}
	}

	return result, nil
}
