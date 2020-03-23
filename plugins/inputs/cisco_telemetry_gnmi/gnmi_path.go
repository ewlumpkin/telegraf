package cisco_telemetry_gnmi

import (
	"fmt"
	"strings"

	"github.com/openconfig/gnmi/proto/gnmi"
)

type gNMIPath gnmi.Path

func parsePath(origin string, path string, target string) (*gnmi.Path, error) {
	var err error
	gnmiPath := gNMIPath{Origin: origin, Target: target}
	err = gnmiPath.parsePath(path, origin)
	if err != nil {
		return nil, err
	}
	baseGNMIPath := gnmi.Path(gnmiPath)
	return &baseGNMIPath, err
}

func (p *gNMIPath) parsePath(path string, origin string) error {
	var err error
	switch origin {
	case "DME":
		err = p.parseDMEElems(path)
	default:
		err = p.parseXPathElems(path)
	}
	return err
}

func (p *gNMIPath) parseXPathElems(path string) error {
	var err error
	if len(path) > 0 && path[0] != '/' {
		err = fmt.Errorf("path does not start with a '/': %s", path)
		return err
	}
	elem := &gnmi.PathElem{}
	start, name, value, end := 0, -1, -1, -1

	path = path + "/"

	for i := 0; i < len(path); i++ {
		if path[i] == '[' {
			if name >= 0 {
				break
			}
			if end < 0 {
				end = i
				elem.Key = make(map[string]string)
			}
			name = i + 1
		} else if path[i] == '=' {
			if name <= 0 || value >= 0 {
				break
			}
			value = i + 1
		} else if path[i] == ']' {
			if name <= 0 || value <= name {
				break
			}
			elem.Key[path[name:value-1]] = strings.Trim(path[value:i], "'\"")
			name, value = -1, -1
		} else if path[i] == '/' {
			if name < 0 {
				if end < 0 {
					end = i
				}

				if end > start {
					elem.Name = path[start:end]
					p.Elem = append(p.Elem, elem)
					p.Element = append(p.Element, path[start:i])
				}

				start, name, value, end = i+1, -1, -1, -1
				elem = &gnmi.PathElem{}
			}
		}
	}
	if name >= 0 || value >= 0 {
		err = fmt.Errorf("Invalid GNMI path: %s", path)
	}
	return err
}

func (p *gNMIPath) parseDMEElems(path string) error {
	var err error
	err = p.parseXPathElems(path)
	return err
}
