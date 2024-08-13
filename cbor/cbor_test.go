package cbor

import (
	"encoding/hex"
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
)

func testDecode(t *testing.T, data string) any {
	t.Helper()
	data = strings.ReplaceAll(data, "\n", "")
	data = strings.ReplaceAll(data, "\r", "")
	data = strings.ReplaceAll(data, "\t", "")
	data = strings.ReplaceAll(data, " ", "")
	bytes, err := hex.DecodeString(data)
	require.NoError(t, err)
	d, err := Unmarshal(bytes)
	require.NoError(t, err)
	return d
}

func TestPublicKeyCredentialRpEntity(t *testing.T) {
	input := `
	a1
  		64
    		6e616d65
  		64
    		41636d65
	`
	output := testDecode(t, input)
	assert.Equal(t, Map{{"name", "Acme"}}, output)
}

func TestPublicKeyCredentialUserEntity(t *testing.T) {
	input := `
 a4                                      
    62                                  
        6964                            
    58 20                               
        3082019330820138a003020102      
        3082019330820138a003020102      
        308201933082                    
    64                                  
        69636f6e                        
    782b                                
        68747470733a2f2f706963732e657861
        6d706c652e636f6d2f30302f702f6142
        6a6a6a707150622e706e67          
    64                                  
        6e616d65                        
    76                                  
        6a6f686e70736d697468406578616d70
        6c652e636f6d                    
    6b                                  
        646973706c61794e616d65          
    6d                                  
        4a6f686e20502e20536d697468      
`
	output := testDecode(t, input)
	val := Map{
		{"id", []uint8{0x30, 0x82, 0x1, 0x93, 0x30, 0x82, 0x1, 0x38, 0xa0, 0x3, 0x2, 0x1, 0x2, 0x30, 0x82, 0x1, 0x93, 0x30, 0x82, 0x1, 0x38, 0xa0, 0x3, 0x2, 0x1, 0x2, 0x30, 0x82, 0x1, 0x93, 0x30, 0x82}},
		{"icon", "https://pics.example.com/00/p/aBjjjpqPb.png"},
		{"name", "johnpsmith@example.com"},
		{"displayName", "John P. Smith"},
	}
	assert.Equal(t, val, output)
}

func TestFloat(t *testing.T) {
	input := `
    C4
      82
         21
         19 6ab3
`
	output := testDecode(t, input)
	assert.Equal(t, uint64(0x4), output) // TODO: This is incorrect.
}

func TestEncodeInt(t *testing.T) {
	testCases := map[int64]string{
		// Unsigned integers
		0:             "00",
		10:            "0a",
		23:            "17",
		24:            "1818",
		25:            "1819",
		255:           "18ff",
		256:           "190100",
		500:           "1901f4",
		1000:          "1903e8",
		65535:         "19ffff",
		65536:         "1a00010000",
		1000000:       "1a000f4240",
		4294967295:    "1affffffff",
		4294967296:    "1b0000000100000000",
		1000000000000: "1b000000e8d4a51000",

		// Negative integers
		-1:             "20",
		-10:            "29",
		-23:            "36",
		-24:            "37",
		-25:            "3818",
		-256:           "38ff",
		-257:           "390100",
		-500:           "3901f3",
		-1000:          "3903e7",
		-65536:         "39ffff",
		-65537:         "3a00010000",
		-1000000:       "3a000f423f",
		-4294967296:    "3affffffff",
		-4294967297:    "3b0000000100000000",
		-1000000000000: "3b000000e8d4a50fff",
	}

	for val, expected := range testCases {
		t.Run(fmt.Sprintf("%d encodes into %s", val, expected), func(t *testing.T) {
			encoded, err := Marshal(val)
			require.NoError(t, err)

			encodedHex := hex.EncodeToString(encoded)
			assert.Equal(t, expected, encodedHex)
		})
	}
}

func TestEncodeString(t *testing.T) {
	testCases := map[string]string{
		"":                        "60",
		"a":                       "6161",
		"Hello":                   "6548656c6c6f",
		"CBOR":                    "6443424f52",
		"12345678901234567890123": "773132333435363738393031323334353637383930313233",
		"https://pics.example.com/00/p/aBjjjpqPb.png": "782b68747470733a2f2f706963732e6578616d706c652e636f6d2f30302f702f61426a6a6a707150622e706e67",
	}

	for val, expected := range testCases {
		t.Run(fmt.Sprintf("%q encodes into %s", val, expected), func(t *testing.T) {
			encoded, err := Marshal(val)
			require.NoError(t, err)

			encodedHex := hex.EncodeToString(encoded)
			assert.Equal(t, expected, encodedHex)
		})
	}
}

func TestEncodeByteArray(t *testing.T) {
	testCases := []struct {
		input    []byte
		expected string // Expected CBOR encoding in hex
	}{
		{[]byte{}, "40"},
		{[]byte{0x01}, "4101"},
		{[]byte{0x00, 0x01, 0x02, 0x03}, "4400010203"},
		{[]byte("Hello"), "4548656c6c6f"},
		{[]byte{0xff, 0x00, 0xaa, 0x55}, "44ff00aa55"},
	}
	for _, v := range testCases {
		t.Run(fmt.Sprintf("%#v encodes into %s", v.input, v.expected), func(t *testing.T) {
			encoded, err := Marshal(v.input)
			require.NoError(t, err)

			encodedHex := hex.EncodeToString(encoded)
			assert.Equal(t, v.expected, encodedHex)
		})
	}
}

func TestEncodeStringArray(t *testing.T) {
	tests := []struct {
		input    []string
		expected string // Expected CBOR encoding in hex
	}{
		{[]string{}, "80"},
		{[]string{"a"}, "816161"},
		{[]string{"Hello", "World"}, "826548656c6c6f65576f726c64"},
		{[]string{"CBOR", "is", "fun"}, "836443424f526269736366756e"},
		{[]string{"", "a", "ab", "abc"}, "8460616162616263616263"},
		{[]string{"12345678901234567890123", "short", ""}, "837731323334353637383930313233343536373839303132336573686f727460"},
	}

	for _, v := range tests {
		t.Run(fmt.Sprintf("%#v encodes into %s", v.input, v.expected), func(t *testing.T) {
			encoded, err := Marshal(v.input)
			require.NoError(t, err)

			encodedHex := hex.EncodeToString(encoded)
			assert.Equal(t, v.expected, encodedHex)
		})
	}
}

func TestEncodeIntArray(t *testing.T) {
	encoded, err := Marshal([]int{0, 10, 23, 24, 25, 255, 256, 500, 1000, 65535, 65536, 1000000, 4294967295, 4294967296, 1000000000000, -1, -27, -245, -1024})
	require.NoError(t, err)

	encodedHex := hex.EncodeToString(encoded)
	assert.Equal(t, "93000a171818181918ff1901001901f41903e819ffff1a000100001a000f42401affffffff1b00000001000000001b000000e8d4a5100020381a38f43903ff", encodedHex)
}

func TestEncodeFloat(t *testing.T) {
	encoded, err := Marshal(float32(65504.0))
	require.NoError(t, err)

	encodedHex := hex.EncodeToString(encoded)
	assert.Equal(t, "fa477fe000", encodedHex)
}

func TestDecodeHalfFloat(t *testing.T) {
	dec, err := Unmarshal([]byte{0xf9, 0x3c, 0x00})
	require.NoError(t, err)
	assert.Equal(t, float32(1.0), dec)
}

func TestEncodeMap(t *testing.T) {
	theMap := map[string]int{
		"a": 1,
		"b": 2,
		"c": 3,
	}
	encoded, err := Marshal(theMap)
	require.NoError(t, err)
	decoded, err := Unmarshal(encoded)
	require.NoError(t, err)
	result := decoded.(Map)
	assert.ElementsMatch(t, result, Map{
		{"a", uint(1)},
		{"b", uint(2)},
		{"c", uint(3)},
	})
}

func TestEncodeStructArray(t *testing.T) {
	type SomeStruct struct {
		Name  string `cbor:""`
		Email string `cbor:""`
	}
	val := SomeStruct{"Paul", "paul.appleseed@example.com"}
	encoded, err := Marshal(val)
	require.NoError(t, err)

	assert.Equal(t, "82645061756c781a7061756c2e6170706c6573656564406578616d706c652e636f6d", hex.EncodeToString(encoded))
}

func TestEncodeStructMap(t *testing.T) {
	type SomeStruct struct {
		Name  string `cbor:"name"`
		Email string `cbor:"email"`
	}
	val := SomeStruct{"Paul", "paul.appleseed@example.com"}
	encoded, err := Marshal(&val)
	require.NoError(t, err)

	assert.Equal(t, "a2646e616d65645061756c65656d61696c781a7061756c2e6170706c6573656564406578616d706c652e636f6d", hex.EncodeToString(encoded))
}

type SomeInterface interface {
	SomeMethod() bool
}

type SomeStruct struct {
	Name string `cbor:""`
}

func (s *SomeStruct) SomeMethod() bool { return true }

func TestEncodeInterface(t *testing.T) {
	val := SomeInterface(&SomeStruct{"Paul"})
	encoded, err := Marshal(val)
	require.NoError(t, err)
	assert.Equal(t, "81645061756c", hex.EncodeToString(encoded))
}
