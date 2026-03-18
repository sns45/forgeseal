package vex

import "testing"

func TestParseSeverityLevel(t *testing.T) {
	tests := []struct {
		input    string
		expected SeverityLevel
		wantErr  bool
	}{
		{"critical", SeverityCritical, false},
		{"CRITICAL", SeverityCritical, false},
		{"Critical", SeverityCritical, false},
		{"high", SeverityHigh, false},
		{"medium", SeverityMedium, false},
		{"low", SeverityLow, false},
		{"invalid", SeverityUnknown, true},
		{"", SeverityUnknown, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ParseSeverityLevel(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseSeverityLevel(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if got != tt.expected {
				t.Errorf("ParseSeverityLevel(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestExceedsThreshold(t *testing.T) {
	tests := []struct {
		name      string
		counts    map[SeverityLevel]int
		threshold SeverityLevel
		expected  bool
	}{
		{
			name:      "critical threshold, has critical",
			counts:    map[SeverityLevel]int{SeverityCritical: 1, SeverityHigh: 3},
			threshold: SeverityCritical,
			expected:  true,
		},
		{
			name:      "critical threshold, only high",
			counts:    map[SeverityLevel]int{SeverityHigh: 3, SeverityMedium: 5},
			threshold: SeverityCritical,
			expected:  false,
		},
		{
			name:      "high threshold, has critical",
			counts:    map[SeverityLevel]int{SeverityCritical: 1},
			threshold: SeverityHigh,
			expected:  true,
		},
		{
			name:      "high threshold, has high",
			counts:    map[SeverityLevel]int{SeverityHigh: 2, SeverityLow: 10},
			threshold: SeverityHigh,
			expected:  true,
		},
		{
			name:      "high threshold, only medium and low",
			counts:    map[SeverityLevel]int{SeverityMedium: 5, SeverityLow: 10},
			threshold: SeverityHigh,
			expected:  false,
		},
		{
			name:      "medium threshold, has medium",
			counts:    map[SeverityLevel]int{SeverityMedium: 3},
			threshold: SeverityMedium,
			expected:  true,
		},
		{
			name:      "low threshold, has low",
			counts:    map[SeverityLevel]int{SeverityLow: 1},
			threshold: SeverityLow,
			expected:  true,
		},
		{
			name:      "low threshold, only unknown",
			counts:    map[SeverityLevel]int{SeverityUnknown: 5},
			threshold: SeverityLow,
			expected:  false,
		},
		{
			name:      "no vulns at all",
			counts:    map[SeverityLevel]int{},
			threshold: SeverityLow,
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &TriageResult{CountBySeverity: tt.counts}
			got := ExceedsThreshold(result, tt.threshold)
			if got != tt.expected {
				t.Errorf("ExceedsThreshold() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestThresholdErrorMessage(t *testing.T) {
	err := &ThresholdError{
		Threshold: SeverityHigh,
		Counts: map[SeverityLevel]int{
			SeverityCritical: 2,
			SeverityHigh:     3,
			SeverityMedium:   10,
		},
	}

	msg := err.Error()
	if msg == "" {
		t.Fatal("expected non-empty error message")
	}
	// Should mention threshold
	if !contains(msg, "high") {
		t.Errorf("expected threshold in message, got: %s", msg)
	}
	// Should mention critical and high counts (at or above threshold)
	if !contains(msg, "2 critical") {
		t.Errorf("expected critical count in message, got: %s", msg)
	}
	if !contains(msg, "3 high") {
		t.Errorf("expected high count in message, got: %s", msg)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
