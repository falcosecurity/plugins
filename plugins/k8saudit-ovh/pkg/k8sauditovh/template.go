package k8sauditovh

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"time"
)

var bColors = map[string][]byte{
	"green":   {27, 91, 52, 50, 109},
	"white":   {27, 91, 52, 55, 109},
	"yellow":  {27, 91, 52, 51, 109},
	"red":     {27, 91, 52, 49, 109},
	"blue":    {27, 91, 52, 52, 109},
	"magenta": {27, 91, 52, 53, 109},
	"cyan":    {27, 91, 52, 54, 109},
	"reset":   {27, 91, 48, 109},
}

func bColor(c string) string {
	if s, ok := bColors[c]; ok {
		return string(s)
	}
	return ""
}

var colors = map[string][]byte{
	"green":   {27, 91, 51, 50, 109},
	"white":   {27, 91, 51, 55, 109},
	"yellow":  {27, 91, 51, 51, 109},
	"red":     {27, 91, 51, 49, 109},
	"blue":    {27, 91, 51, 52, 109},
	"magenta": {27, 91, 51, 53, 109},
	"cyan":    {27, 91, 51, 54, 109},
	"reset":   {27, 91, 48, 109},
}

func color(c string) string {
	if s, ok := colors[c]; ok {
		return string(s)
	}
	return ""
}

func date(v float64, f ...string) string {

	t := time.Unix(int64(v), 0)

	if len(f) == 0 {
		return t.Format("2006-01-02 15:04:05")
	}

	return t.Format(f[0])
}

func join(s ...string) string {
	return strings.Join(s[1:], s[0])
}

func concat(s ...string) string {
	var b bytes.Buffer
	for _, v := range s {
		b.WriteString(v)
	}
	return b.String()
}

func duration(v interface{}, factor float64) (string, error) {
	var d time.Duration
	switch value := v.(type) {
	case string:
		f, err := strconv.ParseFloat(value, 64)
		if err != nil {
			return "", err
		}
		d = time.Duration(f * factor)
	case float64:
		d = time.Duration(value * factor)
	case int64:
		d = time.Duration(value * int64(factor))
	default:
		return "", fmt.Errorf("Invalid type %T for duration", v)
	}
	return d.String(), nil
}

func get(v map[string]interface{}, k string) interface{} {
	return v[k]
}

var columnLength []int

func column(sep string, s ...string) (string, error) {
	if columnLength == nil {
		columnLength = make([]int, len(s))
	}

	if len(s) != len(columnLength) {
		return "", fmt.Errorf("Invalid number of arguments to 'column'")
	}

	for k, v := range s {
		if len(v) > columnLength[k] {
			columnLength[k] = len(v)
		} else {
			s[k] = v + strings.Repeat(" ", columnLength[k]-len(v))
		}
	}

	return strings.Join(s, sep), nil
}

func begin(v interface{}, substr string) bool {
	var value string

	switch v.(type) {
	case string:
		value = v.(string)
	default:
		value = fmt.Sprintf("%v", v)
	}
	return strings.HasPrefix(value, substr)
}

func contain(v interface{}, substr string) bool {
	var value string

	switch v.(type) {
	case string:
		value = v.(string)
	default:
		value = fmt.Sprintf("%v", v)
	}
	return strings.Contains(value, substr)
}

var syslogLevels = map[int]string{
	0: "emerg",
	1: "alert",
	2: "crit",
	3: "err",
	4: "warn",
	5: "notice",
	6: "info",
	7: "debug",
}

func level(v interface{}) (string, error) {
	vFloat, err := toNumber(v)
	if err != nil {
		return "", err
	}

	value, ok := syslogLevels[int(vFloat)]
	if !ok {
		value = fmt.Sprintf("(invalid:%d)", int(vFloat))
	}

	return value, nil
}

func toInt(v interface{}) (int64, error) {
	if f, ok := v.(float64); ok {
		return int64(f), nil
	}
	if s, ok := v.(string); ok {
		f, e := strconv.ParseFloat(s, 64)
		return int64(f), e
	}
	return 0, fmt.Errorf("Invalid type %T for conversion to `int`", v)
}

func toFloat(v interface{}) (float64, error) {
	if f, ok := v.(float64); ok {
		return f, nil
	}
	if s, ok := v.(string); ok {
		f, e := strconv.ParseFloat(s, 64)
		return f, e
	}
	return 0, fmt.Errorf("Invalid type %T for conversion to `float`", v)
}

func toString(v interface{}) string {
	return fmt.Sprintf("%v", v)
}

func toNumber(v interface{}) (float64, error) {
	switch value := v.(type) {
	case string:
		// Try to parse value as float64
		f, err := strconv.ParseFloat(value, 64)
		if err != nil {
			return 0, fmt.Errorf("'%v' can't be parsed as a number", v)
		}
		return f, nil
	case uint:
		return float64(value), nil
	case uint8:
		return float64(value), nil
	case uint16:
		return float64(value), nil
	case uint32:
		return float64(value), nil
	case uint64:
		return float64(value), nil
	case int:
		return float64(value), nil
	case int8:
		return float64(value), nil
	case int16:
		return float64(value), nil
	case int32:
		return float64(value), nil
	case int64:
		return float64(value), nil
	case float32:
		return float64(value), nil
	case float64:
		return value, nil
	default:
		return 0, fmt.Errorf("can't parse type %T as a number", v)
	}
}
