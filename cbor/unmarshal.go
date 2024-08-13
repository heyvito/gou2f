package cbor

import (
	"bufio"
	"bytes"
	"fmt"
	"reflect"
	"strconv"
	"strings"
)

var typeOfMap = reflect.TypeOf((*Map)(nil)).Elem()

func Unmarshal(data []byte) (any, error) {
	return UnmarshalReader(bufio.NewReader(bytes.NewReader(data)))
}

func UnmarshalReader(r *bufio.Reader) (any, error) {
	return NewDecoder(r).decode()
}

type unmarshalCtx struct {
	srcType, dstType   reflect.Type
	srcValue, dstValue reflect.Value
	src                any
	dst                any
}

func UnmarshalInto(dst any, data []byte) error {
	src, err := Unmarshal(data)
	if err != nil {
		return err
	}

	return unmarshalInto(dst, src)
}

func unmarshalInto(dst, src any) error {
	dstType := reflect.TypeOf(dst)
	if dstType.Kind() != reflect.Pointer {
		return fmt.Errorf("%T is not a pointer", dst)
	}
	dstType = dstType.Elem()
	dstPtr := reflect.New(dstType)
	dstValue := dstPtr.Elem()
	srcType := reflect.TypeOf(src)
	srcValue := reflect.ValueOf(src)

	switch dstType.Kind() {
	case reflect.Struct:
		ctx := unmarshalCtx{
			srcType:  srcType,
			dstType:  dstType,
			srcValue: srcValue,
			dstValue: dstValue,
			src:      src,
			dst:      dst,
		}
		if err := unmarshalIntoStruct(ctx); err != nil {
			return err
		}
		break

	case reflect.Bool:
		dstValue.Set(srcValue)
		break
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		dstValue.SetInt(srcValue.Int())
		break
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		dstValue.SetUint(srcValue.Uint())
		break
	case reflect.Float32, reflect.Float64:
		dstValue.SetFloat(srcValue.Float())
		break
	case reflect.Array:
		arr, err := unmarshalIntoArray(dstType.Elem(), src)
		if err != nil {
			return err
		}
		dstValue.Set(arr)
		break
	case reflect.Map:
		mp, err := unmarshalIntoMap(dstType, src)
		if err != nil {
			return err
		}
		dstValue.Set(mp)
		break
	case reflect.Pointer:
		ptrType := dstType.Elem()
		inst := reflect.New(ptrType).Elem().Interface()
		if err := unmarshalInto(inst, src); err != nil {
			return err
		}
		ptrValue := reflect.New(dstType)
		ptrValue.Set(reflect.ValueOf(inst).Addr())
		dstValue.Set(ptrValue)
		break
	case reflect.Slice:
		arr, err := unmarshalIntoArray(dstType.Elem(), src)
		if err != nil {
			return err
		}
		dstValue.Set(arr)
		break
	case reflect.String:
		dstValue.SetString(dstValue.String())
		break

	default:
		return fmt.Errorf("unsupported field type %s", dstType.Name())
	}

	reflect.ValueOf(dst).Elem().Set(dstValue)
	return nil
}

type structField struct {
	name    string
	index   []int
	key     string
	keyType reflect.Kind
	keyRepr any
	field   reflect.StructField
}

func extractFieldsFromStruct(structPath string, t reflect.Type) (arr []structField, err error) {
	for i := range t.NumField() {
		f := t.Field(i)
		tag, ok := f.Tag.Lookup("cbor")
		if !ok {
			continue
		}
		comps := strings.SplitN(tag, ",", 2)
		keySpec := comps[0]
		if len(keySpec) == 0 {
			continue
		}

		fieldFullPath := fmt.Sprintf("%s.%s", structPath, f.Name)
		if strings.ContainsRune(keySpec, ':') {
			// Currently we are only using the `u8` prefix for those tags,
			// but in case we have new ones, it may be added or extended from
			// this point:
			comps = strings.SplitN(keySpec, ":", 2)
			if comps[0] != "u8" {
				return nil, fmt.Errorf("unsupported field prefix type %s for field %s", comps[0], fieldFullPath)
			}

			if comps[1] == "" {
				return nil, fmt.Errorf("unsupported field spec %s for field %s", keySpec, fieldFullPath)
			}

			val := comps[1]
			base := 10
			if strings.HasPrefix(val, "0x") {
				val = strings.TrimPrefix(val, "0x")
				base = 16
			}
			intVal, err := strconv.ParseUint(val, base, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid value %s for field %s: %w", val, fieldFullPath, err)
			}
			arr = append(arr, structField{
				name:    f.Name,
				index:   f.Index,
				key:     val,
				keyType: reflect.Uint64,
				keyRepr: intVal,
				field:   f,
			})
		} else {
			arr = append(arr, structField{
				name:    f.Name,
				index:   f.Index,
				key:     keySpec,
				keyType: reflect.String,
				keyRepr: keySpec,
				field:   f,
			})
		}
	}

	return
}

func unmarshalIntoStruct(ctx unmarshalCtx) error {
	fullPath := ctx.dstType.PkgPath() + "." + ctx.dstType.Name()
	fields, err := extractFieldsFromStruct(fullPath, ctx.dstType)
	if err != nil {
		return err
	}

	// At this point, considering our implementation, ctx.src will be a
	// Map. The next conversion lacks an assertion on purpose: it should explode
	// in case this condition is not satisfied.

	mp := ctx.src.(Map)
	i := reflect.New(ctx.dstType).Elem()
	i.SetZero()

	for _, v := range fields {
		var pair *Pair
		if v.keyType == reflect.Uint64 {
			// All keys are converted to uint64 internally.
			// The other option is a string.
			pair = mp.FindKey(v.keyRepr.(uint64))
		} else {
			pair = mp.FindKey(v.keyRepr.(string))
		}
		if pair == nil {
			continue
		}

		switch v.field.Type.Kind() {
		case reflect.Struct:
			b := reflect.New(v.field.Type)
			b.Elem().SetZero()
			if err = unmarshalInto(b.Interface(), pair.Value); err != nil {
				return err
			}
			i.FieldByIndex(v.field.Index).Set(b.Elem())
			continue
		case reflect.Bool:
			i.FieldByIndex(v.field.Index).SetBool(pair.Value.(bool))
			continue
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			i.FieldByIndex(v.field.Index).SetInt(pair.Value.(int64))
			continue
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			i.FieldByIndex(v.field.Index).SetUint(pair.Value.(uint64))
			continue
		case reflect.Float32, reflect.Float64:
			i.FieldByIndex(v.field.Index).SetFloat(pair.Value.(float64))
			continue
		case reflect.Array:
			arr, err := unmarshalIntoArray(v.field.Type.Elem(), pair.Value)
			if err != nil {
				return err
			}
			i.FieldByIndex(v.field.Index).Set(arr)
			continue
		case reflect.Map:
			mp, err := unmarshalIntoMap(v.field.Type, pair.Value)
			if err != nil {
				return err
			}
			i.FieldByIndex(v.field.Index).Set(mp)
			continue
		case reflect.Pointer:
			ptrType := v.field.Type.Elem()
			inst := reflect.New(ptrType).Elem().Interface()
			if err = unmarshalInto(inst, pair.Value); err != nil {
				return err
			}
			ptrValue := reflect.New(v.field.Type)
			ptrValue.Set(reflect.ValueOf(inst).Addr())
			i.FieldByIndex(v.field.Index).Set(ptrValue)
			continue
		case reflect.Slice:
			arr, err := unmarshalIntoArray(v.field.Type.Elem(), pair.Value)
			if err != nil {
				return err
			}
			i.FieldByIndex(v.field.Index).Set(arr)
			continue
		case reflect.String:
			i.FieldByIndex(v.field.Index).Set(reflect.ValueOf(pair.Value.(string)))
			continue
		}
		return fmt.Errorf("unsupported field type %s", ctx.dstType.Name())
	}

	ctx.dstValue.Set(i)
	return nil
}

func unmarshalIntoMap(mpType reflect.Type, value any) (reflect.Value, error) {
	mpValue := reflect.MakeMap(mpType)
	keyType := mpType.Key()
	valueType := mpType.Elem()
	vValue := reflect.ValueOf(value)

	_, _, _, _ = mpValue, keyType, valueType, vValue

	panic("Not sure what to do here")
}

func unmarshalIntoArray(elem reflect.Type, value any) (reflect.Value, error) {
	targetArr := reflect.New(reflect.SliceOf(elem)).Elem()
	originalArr := reflect.ValueOf(value)
	if originalArr.Kind() != reflect.Slice {
		return reflect.Value{}, fmt.Errorf("expected slice but got %s", originalArr.Kind().String())
	}
	targetArr.Grow(originalArr.Len())

	for i := 0; i < originalArr.Len(); i++ {
		v := originalArr.Index(i)
		obj := reflect.New(elem)
		if err := unmarshalInto(obj.Interface(), v.Interface()); err != nil {
			return reflect.Value{}, err
		}
		targetArr = reflect.Append(targetArr, obj.Elem())
	}

	return targetArr, nil
}
