package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReplacePlaceholders(t *testing.T) {
	cases := []struct {
		expected     string
		err          error
		template     string
		placeholders map[string]string
	}{
		{
			expected:     "abc",
			err:          nil,
			template:     "abc",
			placeholders: map[string]string{},
		},
		{
			expected:     "Abc",
			err:          nil,
			template:     "{a}bc",
			placeholders: map[string]string{"a": "A"},
		},
		{
			expected:     "aBc",
			err:          nil,
			template:     "a{b}c",
			placeholders: map[string]string{"b": "B"},
		},
		{
			expected:     "abC",
			err:          nil,
			template:     "ab{c}",
			placeholders: map[string]string{"c": "C"},
		},
	}
	for _, case_ := range cases {
		actual, err := replacePlaceholders(case_.template, case_.placeholders)
		if case_.err != nil {
			assert.Error(t, case_.err, err)
		} else {
			assert.Equal(t, case_.expected, actual)
		}
	}
}
