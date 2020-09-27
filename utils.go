package main

import "fmt"

func replacePlaceholders(template string, placeholders map[string]string) (string, error) {
	s := -1
	ss := 0
	result := make([]byte, 0, len(template))
	for i, c := range template {
		if s >= 0 {
			if c == '}' {
				n := template[s+1 : i]
				v, ok := placeholders[n]
				if !ok {
					return "", fmt.Errorf("unknown placeholder: %s", n)
				}
				result = append(result, v...)
				ss = i + 1
				s = -1
			}
		} else {
			if c == '{' {
				result = append(result, template[ss:i]...)
				s = i
			}
		}
	}
	if s != -1 {
		return "", fmt.Errorf("unclosed placeholder: %s", template[s:])
	}
	if ss < len(template) {
		result = append(result, template[ss:]...)
	}
	return string(result), nil
}
