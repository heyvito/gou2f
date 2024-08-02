package hid

import "fmt"

type CTAPError byte

func (c CTAPError) Error() string {
	msg, ok := ctapErrorToString[c]
	if !ok {
		msg = "Unknown"
	}
	return fmt.Sprintf("CTAPError: %s (0x%02x)", msg, byte(c))
}

var ctapErrorToString = map[CTAPError]string{
	CTAP1_ERR_SUCCESS:                 "CTAP1_ERR_SUCCESS",
	CTAP1_ERR_INVALID_COMMAND:         "CTAP1_ERR_INVALID_COMMAND",
	CTAP1_ERR_INVALID_PARAMETER:       "CTAP1_ERR_INVALID_PARAMETER",
	CTAP1_ERR_INVALID_LENGTH:          "CTAP1_ERR_INVALID_LENGTH",
	CTAP1_ERR_INVALID_SEQ:             "CTAP1_ERR_INVALID_SEQ",
	CTAP1_ERR_TIMEOUT:                 "CTAP1_ERR_TIMEOUT",
	CTAP1_ERR_CHANNEL_BUSY:            "CTAP1_ERR_CHANNEL_BUSY",
	CTAP1_ERR_LOCK_REQUIRED:           "CTAP1_ERR_LOCK_REQUIRED",
	CTAP1_ERR_INVALID_CHANNEL:         "CTAP1_ERR_INVALID_CHANNEL",
	CTAP2_ERR_CBOR_UNEXPECTED_TYPE:    "CTAP2_ERR_CBOR_UNEXPECTED_TYPE",
	CTAP2_ERR_INVALID_CBOR:            "CTAP2_ERR_INVALID_CBOR",
	CTAP2_ERR_MISSING_PARAMETER:       "CTAP2_ERR_MISSING_PARAMETER",
	CTAP2_ERR_LIMIT_EXCEEDED:          "CTAP2_ERR_LIMIT_EXCEEDED",
	CTAP2_ERR_FP_DATABASE_FULL:        "CTAP2_ERR_FP_DATABASE_FULL",
	CTAP2_ERR_LARGE_BLOB_STORAGE_FULL: "CTAP2_ERR_LARGE_BLOB_STORAGE_FULL",
	CTAP2_ERR_CREDENTIAL_EXCLUDED:     "CTAP2_ERR_CREDENTIAL_EXCLUDED",
	CTAP2_ERR_PROCESSING:              "CTAP2_ERR_PROCESSING",
	CTAP2_ERR_INVALID_CREDENTIAL:      "CTAP2_ERR_INVALID_CREDENTIAL",
	CTAP2_ERR_USER_ACTION_PENDING:     "CTAP2_ERR_USER_ACTION_PENDING",
	CTAP2_ERR_OPERATION_PENDING:       "CTAP2_ERR_OPERATION_PENDING",
	CTAP2_ERR_NO_OPERATIONS:           "CTAP2_ERR_NO_OPERATIONS",
	CTAP2_ERR_UNSUPPORTED_ALGORITHM:   "CTAP2_ERR_UNSUPPORTED_ALGORITHM",
	CTAP2_ERR_OPERATION_DENIED:        "CTAP2_ERR_OPERATION_DENIED",
	CTAP2_ERR_KEY_STORE_FULL:          "CTAP2_ERR_KEY_STORE_FULL",
	CTAP2_ERR_UNSUPPORTED_OPTION:      "CTAP2_ERR_UNSUPPORTED_OPTION",
	CTAP2_ERR_INVALID_OPTION:          "CTAP2_ERR_INVALID_OPTION",
	CTAP2_ERR_KEEPALIVE_CANCEL:        "CTAP2_ERR_KEEPALIVE_CANCEL",
	CTAP2_ERR_NO_CREDENTIALS:          "CTAP2_ERR_NO_CREDENTIALS",
	CTAP2_ERR_USER_ACTION_TIMEOUT:     "CTAP2_ERR_USER_ACTION_TIMEOUT",
	CTAP2_ERR_NOT_ALLOWED:             "CTAP2_ERR_NOT_ALLOWED",
	CTAP2_ERR_PIN_INVALID:             "CTAP2_ERR_PIN_INVALID",
	CTAP2_ERR_PIN_BLOCKED:             "CTAP2_ERR_PIN_BLOCKED",
	CTAP2_ERR_PIN_AUTH_INVALID:        "CTAP2_ERR_PIN_AUTH_INVALID",
	CTAP2_ERR_PIN_AUTH_BLOCKED:        "CTAP2_ERR_PIN_AUTH_BLOCKED",
	CTAP2_ERR_PIN_NOT_SET:             "CTAP2_ERR_PIN_NOT_SET",
	CTAP2_ERR_PUAT_REQUIRED:           "CTAP2_ERR_PUAT_REQUIRED",
	CTAP2_ERR_PIN_POLICY_VIOLATION:    "CTAP2_ERR_PIN_POLICY_VIOLATION",
	CTAP2_ERR_REQUEST_TOO_LARGE:       "CTAP2_ERR_REQUEST_TOO_LARGE",
	CTAP2_ERR_ACTION_TIMEOUT:          "CTAP2_ERR_ACTION_TIMEOUT",
	CTAP2_ERR_UP_REQUIRED:             "CTAP2_ERR_UP_REQUIRED",
	CTAP2_ERR_UV_BLOCKED:              "CTAP2_ERR_UV_BLOCKED",
	CTAP2_ERR_INTEGRITY_FAILURE:       "CTAP2_ERR_INTEGRITY_FAILURE",
	CTAP2_ERR_INVALID_SUBCOMMAND:      "CTAP2_ERR_INVALID_SUBCOMMAND",
	CTAP2_ERR_UV_INVALID:              "CTAP2_ERR_UV_INVALID",
	CTAP2_ERR_UNAUTHORIZED_PERMISSION: "CTAP2_ERR_UNAUTHORIZED_PERMISSION",
	CTAP1_ERR_OTHER:                   "CTAP1_ERR_OTHER",
	CTAP2_ERR_SPEC_LAST:               "CTAP2_ERR_SPEC_LAST",
	CTAP2_ERR_EXTENSION_FIRST:         "CTAP2_ERR_EXTENSION_FIRST",
	CTAP2_ERR_EXTENSION_LAST:          "CTAP2_ERR_EXTENSION_LAST",
	CTAP2_ERR_VENDOR_FIRST:            "CTAP2_ERR_VENDOR_FIRST",
	CTAP2_ERR_VENDOR_LAST:             "CTAP2_ERR_VENDOR_LAST",
}

const (
	CTAP1_ERR_SUCCESS                 = CTAPError(0x00)
	CTAP1_ERR_INVALID_COMMAND         = CTAPError(0x01)
	CTAP1_ERR_INVALID_PARAMETER       = CTAPError(0x02)
	CTAP1_ERR_INVALID_LENGTH          = CTAPError(0x03)
	CTAP1_ERR_INVALID_SEQ             = CTAPError(0x04)
	CTAP1_ERR_TIMEOUT                 = CTAPError(0x05)
	CTAP1_ERR_CHANNEL_BUSY            = CTAPError(0x06)
	CTAP1_ERR_LOCK_REQUIRED           = CTAPError(0x0A)
	CTAP1_ERR_INVALID_CHANNEL         = CTAPError(0x0B)
	CTAP2_ERR_CBOR_UNEXPECTED_TYPE    = CTAPError(0x11)
	CTAP2_ERR_INVALID_CBOR            = CTAPError(0x12)
	CTAP2_ERR_MISSING_PARAMETER       = CTAPError(0x14)
	CTAP2_ERR_LIMIT_EXCEEDED          = CTAPError(0x15)
	CTAP2_ERR_FP_DATABASE_FULL        = CTAPError(0x17)
	CTAP2_ERR_LARGE_BLOB_STORAGE_FULL = CTAPError(0x18)
	CTAP2_ERR_CREDENTIAL_EXCLUDED     = CTAPError(0x19)
	CTAP2_ERR_PROCESSING              = CTAPError(0x21)
	CTAP2_ERR_INVALID_CREDENTIAL      = CTAPError(0x22)
	CTAP2_ERR_USER_ACTION_PENDING     = CTAPError(0x23)
	CTAP2_ERR_OPERATION_PENDING       = CTAPError(0x24)
	CTAP2_ERR_NO_OPERATIONS           = CTAPError(0x25)
	CTAP2_ERR_UNSUPPORTED_ALGORITHM   = CTAPError(0x26)
	CTAP2_ERR_OPERATION_DENIED        = CTAPError(0x27)
	CTAP2_ERR_KEY_STORE_FULL          = CTAPError(0x28)
	CTAP2_ERR_UNSUPPORTED_OPTION      = CTAPError(0x2B)
	CTAP2_ERR_INVALID_OPTION          = CTAPError(0x2C)
	CTAP2_ERR_KEEPALIVE_CANCEL        = CTAPError(0x2D)
	CTAP2_ERR_NO_CREDENTIALS          = CTAPError(0x2E)
	CTAP2_ERR_USER_ACTION_TIMEOUT     = CTAPError(0x2F)
	CTAP2_ERR_NOT_ALLOWED             = CTAPError(0x30)
	CTAP2_ERR_PIN_INVALID             = CTAPError(0x31)
	CTAP2_ERR_PIN_BLOCKED             = CTAPError(0x32)
	CTAP2_ERR_PIN_AUTH_INVALID        = CTAPError(0x33)
	CTAP2_ERR_PIN_AUTH_BLOCKED        = CTAPError(0x34)
	CTAP2_ERR_PIN_NOT_SET             = CTAPError(0x35)
	CTAP2_ERR_PUAT_REQUIRED           = CTAPError(0x36)
	CTAP2_ERR_PIN_POLICY_VIOLATION    = CTAPError(0x37)
	CTAP2_ERR_REQUEST_TOO_LARGE       = CTAPError(0x39)
	CTAP2_ERR_ACTION_TIMEOUT          = CTAPError(0x3A)
	CTAP2_ERR_UP_REQUIRED             = CTAPError(0x3B)
	CTAP2_ERR_UV_BLOCKED              = CTAPError(0x3C)
	CTAP2_ERR_INTEGRITY_FAILURE       = CTAPError(0x3D)
	CTAP2_ERR_INVALID_SUBCOMMAND      = CTAPError(0x3E)
	CTAP2_ERR_UV_INVALID              = CTAPError(0x3F)
	CTAP2_ERR_UNAUTHORIZED_PERMISSION = CTAPError(0x40)
	CTAP1_ERR_OTHER                   = CTAPError(0x7F)
	CTAP2_ERR_SPEC_LAST               = CTAPError(0xDF)
	CTAP2_ERR_EXTENSION_FIRST         = CTAPError(0xE0)
	CTAP2_ERR_EXTENSION_LAST          = CTAPError(0xEF)
	CTAP2_ERR_VENDOR_FIRST            = CTAPError(0xF0)
	CTAP2_ERR_VENDOR_LAST             = CTAPError(0xFF)
)
