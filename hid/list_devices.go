//go:build !linux

package hid

import "github.com/karalabe/hid"

func ListDevices() ([]*Device, error) {
	var devices []*Device
	sysDevices, err := hid.Enumerate(0x00, 0x00)
	if err != nil {
		return nil, err
	}
	for _, v := range sysDevices {

		if v.UsagePage == fidoUsagePage && v.Usage == uint16(fidoUsageU2FHID) {
			dev := v
			devices = append(devices, newDevice(MakeRawDevice(&dev)))
		}
	}

	return devices, nil
}
