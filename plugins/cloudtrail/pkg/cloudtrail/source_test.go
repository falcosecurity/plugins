package cloudtrail

import "testing"

func TestExtractRecordStrings(t *testing.T) {
	tests := []struct {
		name     string
		payload  string
		expected []string
	}{
		{
			name:    "ignores braces inside strings",
			payload: `{"Records":[{"eventType":"AwsApiCall","eventTime":"2025-01-01T00:00:00Z","msg":"contains { and }"},{"eventType":"AwsApiCall","eventTime":"2025-01-01T00:00:01Z","msg":"second record"}]}`,
			expected: []string{
				`{"eventType":"AwsApiCall","eventTime":"2025-01-01T00:00:00Z","msg":"contains { and }"}`,
				`{"eventType":"AwsApiCall","eventTime":"2025-01-01T00:00:01Z","msg":"second record"}`,
			},
		},
		{
			name:    "handles escaped quotes and backslashes",
			payload: `{"Records":[{"eventType":"AwsApiCall","eventTime":"2025-01-01T00:00:00Z","msg":"escaped quote: \" and path: C:\\temp\\{dir}"},{"eventType":"AwsApiCall","eventTime":"2025-01-01T00:00:01Z"}]}`,
			expected: []string{
				`{"eventType":"AwsApiCall","eventTime":"2025-01-01T00:00:00Z","msg":"escaped quote: \" and path: C:\\temp\\{dir}"}`,
				`{"eventType":"AwsApiCall","eventTime":"2025-01-01T00:00:01Z"}`,
			},
		},
		{
			name:    "handles nested objects and arrays",
			payload: `{"Records":[{"eventType":"AwsApiCall","eventTime":"2025-01-01T00:00:00Z","requestParameters":{"items":["{literal}",{"nested":true}],"note":"prefix } suffix"}},{"eventType":"AwsApiCall","eventTime":"2025-01-01T00:00:01Z","resources":[{"arn":"arn:aws:s3:::example"}]}]}`,
			expected: []string{
				`{"eventType":"AwsApiCall","eventTime":"2025-01-01T00:00:00Z","requestParameters":{"items":["{literal}",{"nested":true}],"note":"prefix } suffix"}}`,
				`{"eventType":"AwsApiCall","eventTime":"2025-01-01T00:00:01Z","resources":[{"arn":"arn:aws:s3:::example"}]}`,
			},
		},
		{
			name:     "returns no records for empty array",
			payload:  `{"Records":[]}`,
			expected: []string{},
		},
		{
			name:    "does not emit incomplete trailing record",
			payload: `{"Records":[{"eventType":"AwsApiCall","msg":"complete"},{"eventType":"AwsApiCall","msg":"unterminated {`,
			expected: []string{
				`{"eventType":"AwsApiCall","msg":"complete"}`,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var records [][]byte
			extractRecordStrings([]byte(tt.payload), &records)

			if len(records) != len(tt.expected) {
				t.Fatalf("expected %d records, got %d", len(tt.expected), len(records))
			}

			for i, record := range records {
				if string(record) != tt.expected[i] {
					t.Fatalf("record %d mismatch: got %q want %q", i, string(record), tt.expected[i])
				}
			}
		})
	}
}
