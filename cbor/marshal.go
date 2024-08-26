package cbor

import (
	"bytes"
	"fmt"
	"math"
	"reflect"
	"strconv"
	"strings"
	"unsafe"
)

// #cgo CFLAGS: -g -Wall
// #include <stdlib.h>
// #if __has_include(<stdint.h>)
// #include<stdint.h>
// #endif
// void marshalInteger(int64_t n, uint8_t buf[9], uint8_t *len, uint8_t mt) {
//     uint64_t ui = n >> 63;
//     if (mt == 0) {
//         mt = ui & 0x20;
//     }
//     ui ^= n;
//     if (ui < 24) {
//         buf[0] = mt + ui;
//         *len = 1;
//     } else if (ui < 256) {
//         buf[0] = mt + 24;
//         buf[1] = ui & 0xFF;
//         *len = 2;
//     } else if (ui < 65536) {
//         buf[0] = mt + 25;
//         buf[1] = ui >> 8;
//         buf[2] = ui;
//         *len = 3;
//     } else if (ui < 4294967296) {
//         buf[0] = mt + 26;
//         buf[1] = ui >> 24;
//         buf[2] = ui >> 16;
//         buf[3] = ui >> 8;
//         buf[4] = ui;
//         *len = 5;
//     } else {
//         buf[0] = mt + 27;
//         buf[1] = ui >> 56;
//         buf[2] = ui >> 48;
//         buf[3] = ui >> 40;
//         buf[4] = ui >> 32;
//         buf[5] = ui >> 24;
//         buf[6] = ui >> 16;
//         buf[7] = ui >> 8;
//         buf[8] = ui;
//         *len = 9;
//     }
// }
import "C"

func marshalInteger(v any) ([]byte, error) {
	return marshalNumber(v, 0x00)
}

func marshalNumber(v any, majorType byte) ([]byte, error) {
	t := reflect.TypeOf(v)
	rv := reflect.ValueOf(v)
	var value C.int64_t
	switch t.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		value = C.int64_t(rv.Int())
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		value = C.int64_t(rv.Uint())
	default:
		return nil, fmt.Errorf("unsupported type %v", t)
	}

	var buf [9]C.uint8_t
	var bufLen C.uint8_t
	C.marshalInteger(C.int64_t(value), &buf[0], &bufLen, C.uint8_t(majorType))

	goBuf := C.GoBytes(unsafe.Pointer(&buf[0]), C.int(bufLen))
	return goBuf, nil
}

func Marshal(v any) ([]byte, error) {
	if v == nil {
		return []byte{0xf6}, nil
	}

	rt := reflect.TypeOf(v)
	switch rt.Kind() {
	case reflect.Complex64, reflect.Complex128, reflect.Chan, reflect.Func,
		reflect.UnsafePointer, reflect.Uintptr, reflect.Invalid:
		return nil, fmt.Errorf("cannot marshal %s", rt.String())

	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return marshalInteger(v)

	case reflect.Float32, reflect.Float64:
		return marshalFloat(v)

	case reflect.Bool:
		if v.(bool) {
			return []byte{0xf5}, nil
		}
		return []byte{0xf4}, nil

	case reflect.Array, reflect.Slice:
		return marshalArray(v)

	case reflect.Interface:
		rv := reflect.ValueOf(v)
		if rv.IsNil() {
			return Marshal(nil)
		}
		return Marshal(rv.Elem().Interface())

	case reflect.Struct:
		return marshalStruct(v)

	case reflect.Map:
		return marshalMap(v)

	case reflect.String:
		return marshalString(v.(string))

	case reflect.Pointer:
		rv := reflect.ValueOf(v)
		if rv.IsNil() {
			return Marshal(nil)
		}
		return Marshal(rv.Elem().Interface())
	}

	panic("unimplemented")
}

func arrayIncludes[T ~[]S, S comparable](arr T, elem S) bool {
	for _, v := range arr {
		if v == elem {
			return true
		}
	}
	return false
}

func marshalStruct(v any) ([]byte, error) {
	rt := reflect.TypeOf(v)
	rv := reflect.ValueOf(v)
	buf := bytes.NewBuffer(nil)
	isMap := false
	isFirst := true
	items := 0
	for i := range rt.NumField() {
		mapName, ok := rt.Field(i).Tag.Lookup("cbor")
		if !ok {
			continue
		}
		mapNameOpts := strings.Split(mapName, ",")
		mapName = mapNameOpts[0]
		omitEmpty := arrayIncludes(mapNameOpts, "omitempty")

		if isFirst && mapName != "" {
			isMap = true
		} else if !isFirst && mapName == "" && isMap {
			return nil, fmt.Errorf("struct %s has cbor tags with and without value. Inconsistency found on field %s", rt.String(), rt.Field(i).Name)
		}
		isFirst = false

		rawVal := rv.Field(i)
		val := rawVal.Interface()
		if omitEmpty && isEmpty(rawVal) {
			continue
		}
		v, err := Marshal(val)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal field %s: %w", rt.Field(i).Name, err)
		}
		if isMap {
			var theMapName any
			if strings.HasPrefix(mapName, "u8:") {
				value := strings.SplitN(mapName, ":", 2)[1]
				if strings.HasPrefix(value, "0x") {
					theMapName, err = strconv.ParseInt(strings.TrimPrefix(value, "0x"), 16, 8)
				} else {
					theMapName, err = strconv.ParseInt(value, 10, 8)
				}
			} else {
				theMapName = mapName
			}
			k, err := Marshal(theMapName)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal field %s: %w", rt.Field(i).Name, err)
			}
			buf.Write(k)
		}
		items++
		buf.Write(v)
	}

	majorType := uint8(0x04)
	if isMap {
		majorType = 0x05
	}

	l, err := marshalNumber(items, majorType<<5)
	if err != nil {
		return nil, err
	}
	return append(l, buf.Bytes()...), nil
}

func isEmpty(val reflect.Value) bool {
	switch val.Kind() {
	case reflect.Invalid:
		return true
	case reflect.Array, reflect.Map, reflect.Slice:
		return val.IsNil() || val.Len() == 0
	case reflect.Interface, reflect.Pointer:
		return val.IsNil()

	default:
		return false
	}
}

func marshalMap(v any) ([]byte, error) {
	rv := reflect.ValueOf(v)
	buffer := bytes.NewBuffer(nil)
	pairs := 0
	iter := rv.MapRange()
	for iter.Next() {
		key := iter.Key().Interface()
		value := iter.Value().Interface()
		encodedKey, err := Marshal(key)
		if err != nil {
			return nil, fmt.Errorf("cannot marshal map key: %v", err)
		}
		encodedValue, err := Marshal(value)
		if err != nil {
			return nil, fmt.Errorf("cannot marshal map value: %v", err)
		}
		buffer.Write(encodedKey)
		buffer.Write(encodedValue)
		pairs++
	}

	l, err := marshalNumber(pairs, 0x05<<5)
	if err != nil {
		return nil, err
	}

	return append(l, buffer.Bytes()...), nil
}

func marshalFloat(v any) ([]byte, error) {
	switch f := v.(type) {
	case float32:
		data := make([]byte, 5)
		data[0] = 7<<5 | 26
		enc.PutUint32(data[1:], math.Float32bits(f))
		return data, nil

	case float64:
		data := make([]byte, 9)
		data[0] = 7<<5 | 27
		enc.PutUint64(data[1:], math.Float64bits(f))
		return data, nil
	}

	panic("unreachable")
}

func marshalString(s string) ([]byte, error) {
	l, err := marshalNumber(len(s), 3<<5)
	if err != nil {
		return nil, err
	}
	return append(l, []byte(s)...), nil
}

func marshalArray(v any) ([]byte, error) {
	rt := reflect.TypeOf(v)
	rv := reflect.ValueOf(v)
	re := rt.Elem().Kind()
	var l int
	if rt.Kind() == reflect.Array {
		l = rv.Type().Len()
	} else {
		l = rv.Len()
	}

	if re == reflect.Uint8 {
		lArr, err := marshalNumber(l, 0x02<<5)
		if err != nil {
			return nil, err
		}
		return append(lArr, v.([]byte)...), nil
	}

	lArr, err := marshalNumber(l, 0x04<<5)
	if err != nil {
		return nil, err
	}
	data := bytes.NewBuffer(nil)
	data.Write(lArr)
	for i := 0; i < l; i++ {
		buf, err := Marshal(rv.Index(i).Interface())
		if err != nil {
			return nil, fmt.Errorf("failed to marshal array element %d: %v", i, err)
		}
		data.Write(buf)
	}

	return data.Bytes(), nil
}
