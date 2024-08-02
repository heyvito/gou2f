package hid

// BEGIN INCLUDE FROM https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/inc/u2f_hid.h
// Common U2F HID transport header - Review Draft
// 2014-10-08
// Editor: Jakob Ehrensvard, Yubico, jakob@yubico.com

// Those constants were translated from the C header for U2F HID

// hidReportSize is the default size of raw HID report
const hidReportSize = 64

// cidBroadcast is the broadcast channel ID
const cidBroadcast = 0xFFFFFFFF

// typeMask is the frame type mask
const typeMask byte = 0x80

// typeInit is the initial frame identifier
const typeInit byte = 0x80

// typeCon is the continuation frame identifier
const typeCont byte = 0x00

// fidoUsagePage is the FIDO alliance HID usage page
const fidoUsagePage uint16 = 0xf1d0

// fidoUsageU2FHID is the U2FHID usage for top-level collection
const fidoUsageU2FHID byte = 0x01

// fidoUsageDataIn is the raw IN data report
const fidoUsageDataIn byte = 0x20

// fidoUsageDataOut is raw OUT data report
const fidoUsageDataOut byte = 0x21

// u2fHIDInterfaceVersion is the current interface implementation version
const u2fHIDInterfaceVersion byte = 2

// u2fHIDTransactionTimeout is the default message timeout in ms
const u2fHIDTransactionTimeout uint16 = 3000 // TODO: Confirm type

// u2fHIDPing identifies the command to echo data through local processor only
const u2fHIDPing byte = typeInit | 0x01

// u2fHIDMessage identifies the command to send U2F message frame
const u2fHIDMessage byte = typeInit | 0x03

// u2fHIDLock identifies the command to lock the current channel
const u2fHIDLock byte = typeInit | 0x04

// u2fHIDInit identifies the command to initialize a channel
const u2fHIDInit byte = typeInit | 0x06

// u2fHIDWink identifies the command to send device identification wink
const u2fHIDWink byte = typeInit | 0x08

const u2fHIDCTAPCBOR byte = typeInit | 0x10

// u2fHIDSync identifies the command to resync the protocol
const u2fHIDSync byte = typeInit | 0x3C

// u2fHIDError idcentifies an error response
const u2fHIDError byte = typeInit | 0x3f

// u2fHIDVendorFirst is the first vendor-defined command
const u2fHIDVendorFirst byte = typeInit | 0x40

// u2fHIDVendorLast is the last vendor-defined command
const u2fHIDVendorLast byte = typeInit | 0x7f

// initNonceSize is the size of channel initialisation challenge
const initNonceSize = 8

// capFlagWink is the capability flag indicating whether the device supports
// the WINK command
const capFlagWink byte = 0x01

// errNone indicates no error
const errNone byte = 0x00

// errInvalidCommand indicates that the provided command is invalid
const errInvalidCommand byte = 0x01

// errInvalidParameter indicates that provided parameter is invalid
const errInvalidParameter byte = 0x02

// errInvalidMessageLength indicates an invalid message length
const errInvalidMessageLength byte = 0x03

// errInvalidMessageSequencing indicates an invalid message sequencing number
const errInvalidMessageSequencing byte = 0x04

// errMessageTimeout indicates that the message has timed out
const errMessageTimeout byte = 0x05

// errChannelBusy indicates that the selected channel is busy
const errChannelBusy byte = 0x06

// errLockRequired indicates that the issued command requires a channel lock to be in place
const errLockRequired byte = 0x0a

// errSyncFail indicates that the SYNC command failed
const errSyncFail byte = 0x0b

// errOther indicates an unspecified error
const errOther byte = 0x7F

// END INCLUDE FROM https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/inc/u2f_hid.h

// BEGIN INCLUDE FROM https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/inc/u2f.h
// Common U2F raw message format header - Review Draft
// 2014-10-08
// Editor: Jakob Ehrensvard, Yubico, jakob@yubico.com

// U2F native commands

// u2fRegister represents the registration command
const u2fRegister byte = 0x01

// u2fAuthenticate represents the authenticate/sign command
const u2fAuthenticate byte = 0x02

// u2fVersion represents the read version string command
const u2fVersion byte = 0x03

const u2fGetInfo = 0x04

const ctapAuthenticatorClientPIN byte = 0x06

const ctapAuthenticatorCredentialManagement byte = 0x0A

const ctapAuthenticatorCredentialManagementPreview byte = 0x41

const (
	ctapAuthenticatorCredMgmtGetCredsMetadata                      byte = 0x01
	ctapAuthenticatorCredMgmtEnumerateRPsBegin                     byte = 0x02
	ctapAuthenticatorCredMgmtEnumerateRPsGetNextRP                 byte = 0x03
	ctapAuthenticatorCredMgmtEnumerateCredentialsBegin             byte = 0x04
	ctapAuthenticatorCredMgmtEnumerateCredentialsGetNextCredential byte = 0x05
	ctapAuthenticatorCredMgmtDeleteCredential                      byte = 0x06
	ctapAuthenticatorCredMgmtUpdateUserInformation                 byte = 0x07
)

// u2fVendorFirst represents the first vendor defined command
const u2fVendorFirst byte = 0x40

// u2fVendorLast represents the last vendor defined command
const u2fVendorLast byte = 0xbf

// u2fCmdRegister command defines

// u2fRegisterId represents the version 2 registration identifier
const u2fRegisterId byte = 0x05

// u2fRegisterHashId represents the version 2 hash identifier
const u2fRegisterHashId byte = 0x00

// Software Errors from APDU commands

const u2fSwNoError uint16 = 0x9000                 // SW_NO_ERROR
const u2fSwWrongData uint16 = 0x6A80               // SW_WRONG_DATA
const u2fSwConditionsNotSatisfied uint16 = 0x6985  // SW_CONDITIONS_NOT_SATISFIED
const u2fSwCommandNotAllowed uint16 = 0x6986       // SW_COMMAND_NOT_ALLOWED
const u2fSwInstructionNotSupported uint16 = 0x6D00 // SW_INS_NOT_SUPPORTED

// END INCLUDE FROM https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/inc/u2f.h
