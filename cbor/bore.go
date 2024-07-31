package cbor

import "reflect"

func MustBore[T any](obj any, expr string) (ok bool, result T) {
	var err error
	ok, result, err = Bore[T](obj, expr)
	if err != nil {
		panic(err)
	}
	return
}

func Bore[T any](obj any, expr string) (ok bool, result T, err error) {
	steps, err := parseBoreExpr(expr)
	if err != nil {
		return
	}

loop:
	for _, s := range steps {
		rt := reflect.TypeOf(obj)
		rv := reflect.ValueOf(obj)

		if s.RequiredType == reflect.Array {
			k := rt.Kind()
			if k != reflect.Slice && k != reflect.Array {
				ok = false
				return
			}
			if rv.Len() < s.ExprValue.(int) {
				ok = false
				return
			}
			obj = rv.Index(s.ExprValue.(int)).Interface()
			continue
		}

		var mapObj Map
		if mapObj, ok = obj.(Map); !ok {
			return
		}

		for _, v := range mapObj {
			if v.Key == s.ExprValue {
				obj = v.Value
				continue loop
			}
		}

		ok = false
		return
	}

	result, ok = obj.(T)
	return
}
