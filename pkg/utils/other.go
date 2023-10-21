package utils

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

func ConverFromBytes(b int64) string {
	bf := float64(b)
	for _, unit := range []string{"", "Ki", "Mi", "Gi", "Ti", "Pi", "Ei", "Zi"} {
		if math.Abs(bf) < 1024.0 {
			return fmt.Sprintf("%3.1f%sB", bf, unit)
		}
		bf /= 1024.0
	}
	return fmt.Sprintf("%.1fYiB", bf)
}

func ConvertToBytes(s string) (int64, error) {
	// Remove any leading or trailing white space from the input string
	s = strings.TrimSpace(s)

	if s == "" {
		return 0, fmt.Errorf("empty string")
	}

	// If the input string is "0", return 0 bytes
	if s == "0" {
		return 0, nil
	}

	// Get the numeric value as a string
	numStr := s[:len(s)-2]

	// Get the suffix as a string
	suffix := strings.ToLower(s[len(s)-2:])

	// Convert the numeric value to an integer
	num, err := strconv.ParseInt(numStr, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("unable to convert numeric value '%s' to integer: %v", numStr, err)
	}

	// Calculate the number of bytes corresponding to the suffix
	var bytes int64
	switch suffix {
	case "kb":
		bytes = num * 1024
	case "mb":
		bytes = num * 1024 * 1024
	case "gb":
		bytes = num * 1024 * 1024 * 1024
	default:
		suffix := strings.ToLower(s[len(s)-1:])
		if suffix == "b" {
			numStr := s[:len(s)-1]
			num, err := strconv.ParseInt(numStr, 10, 64)
			if err != nil {
				return 0, fmt.Errorf("unable to convert numeric value '%s' to integer: %v", numStr, err)
			}
			return num, nil
		}

		return 0, fmt.Errorf("invalid suffix: %s", suffix)
	}

	return bytes, nil
}
