package gou2f

import "github.com/heyvito/gou2f/hid"

func ListDevices() ([]*hid.Device, error) {
	return hid.ListDevices()
}
