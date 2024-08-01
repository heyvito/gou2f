package hid

import (
	"encoding/hex"
	"fmt"
	"github.com/karalabe/hid"
)

const u2fDebug = false

func MakeRawDevice(base *hid.DeviceInfo) *RawDevice {
	return &RawDevice{Device: base}
}

type RawDevice struct {
	Device *hid.DeviceInfo
	Handle hid.Device
}

func (d *RawDevice) Open() error {
	handle, err := d.Device.Open()
	if err != nil {
		return err
	}
	d.Handle = handle
	return nil
}

func (d *RawDevice) Close() error {
	if d.Handle == nil {
		return nil
	}
	if err := d.Handle.Close(); err != nil {
		return err
	}
	d.Handle = nil
	return nil
}

func (d *RawDevice) Write(data []byte) (int, error) {
	if u2fDebug {
		fmt.Printf("Device write: \n%s\n\n", hex.Dump(data))
	}
	return d.Handle.Write(data)
}

func (d *RawDevice) Read(data []byte) (int, error) {
	n, err := d.Handle.Read(data)
	if err == nil && u2fDebug {
		fmt.Printf("Device read: \n%s\n\n", hex.Dump(data[:n]))
	}
	return n, err
}
