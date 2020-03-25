package cisco_telemetry_gnmi

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/openconfig/gnmi/proto/gnmi"
)

type gNMIPath gnmi.Path

// Parse path to path-buffer and tag-field
func pathToMetricAttrs(path *gnmi.Path, tags map[string]string, aliases map[string]string, prefix string) (string, string, string) {
	var aliasPath string
	builder := bytes.NewBufferString(prefix)

	// Prefix with origin
	if len(path.Origin) > 0 {
		builder.WriteString(path.Origin)
		builder.WriteRune(':')
	}

	// Parse generic keys from prefix
	for _, elem := range path.Elem {
		if len(elem.Name) > 0 {
			builder.WriteRune('/')
			builder.WriteString(elem.Name)
		}
		name := builder.String()

		if _, exists := aliases[name]; exists {
			aliasPath = name
		}

		if tags != nil {
			for key, val := range elem.Key {
				key = strings.Replace(key, "-", "_", -1)

				// Use short-form of key if possible
				if _, exists := tags[key]; exists {
					tags[name+"/"+key] = val
				} else {
					tags[key] = val
				}

			}
		}
	}
	pathString := builder.String()
	var noOriginPathString string
	if len(path.Origin) > 0 {
		noOriginPathString = prefix + pathString[len(prefix)+len(path.Origin)+1:]
	}
	return pathString, noOriginPathString, aliasPath
}

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

// DME Path does not follow YANG XPath encoding rules.
// For instance, [] are liable to be directly in path, not a key.
// /sys/intf/phys-[eth1/1] is an example, NX expects phys-[eth1/1] to be a Path elem
// There are query conditions that we do need to map to keys, these start with ?
// /sys/intf/?query-condition[query-target=subtree&target-subtree-class=rmonDot3Stats]/
// So there is some separate state to track in parsing compared to YANG.
func (p *gNMIPath) parseDMEElems(path string) error {
	var err error
	if len(path) > 0 && path[0] != '/' {
		err = fmt.Errorf("path does not start with a '/': %s", path)
		return err
	}
	elem := &gnmi.PathElem{}
	start, name, value, end, condition, inCondition, keyedPath := 0, -1, -1, -1, false, false, false

	path = path + "/"

	for i := 0; i < len(path); i++ {
		if condition == true {
			if path[i] == '[' {
				if name >= 0 {
					break
				}
				if end < 0 {
					end = i
					elem.Key = make(map[string]string)
				}
				name = i + 1
			} else if path[i] == '=' && inCondition != true {
				if name <= 0 || value >= 0 {
					break
				}
				value = i + 1
				inCondition = true
			} else if path[i] == ']' {
				if name <= 0 || value <= name {
					break
				}
				elem.Key[path[name:value-1]] = strings.Trim(path[value:i], "'\"")
				name, value, condition, inCondition = -1, -1, false, false
			}
		} else if path[i] == '[' {
			keyedPath = true
		} else if keyedPath == true && path[i] == ']' {
			keyedPath = false
		} else if keyedPath != true && path[i] == '/' {
			if name < 0 {
				if end < 0 {
					end = i
				}

				if end > start {
					elem.Name = path[start:end]
					p.Elem = append(p.Elem, elem)
					p.Element = append(p.Element, path[start:i])
				}

				start, name, value, end, condition, inCondition = i+1, -1, -1, -1, false, false
				elem = &gnmi.PathElem{}
			}
		} else if path[i] == '?' {
			condition = true
		}
	}
	if name >= 0 || value >= 0 {
		err = fmt.Errorf("Invalid GNMI path: %s", path)
	}
	return err
}
