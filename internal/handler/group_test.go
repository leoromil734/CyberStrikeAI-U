package handler

import (
	"strings"
	"testing"
)

func TestValidateGroupFieldsAllowsNormalNamesAndIcons(t *testing.T) {
	tests := []struct {
		name, icon, wantName, wantIcon string
	}{
		{"  日常安全巡检  ", " 📁 ", "日常安全巡检", "📁"},
		{"研发 & 测试", "", "研发 & 测试", ""},
		{strings.Repeat("分", maxGroupNameRunes), strings.Repeat("📁", maxGroupIconRunes), strings.Repeat("分", maxGroupNameRunes), strings.Repeat("📁", maxGroupIconRunes)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name, icon, err := validateGroupFields(tt.name, tt.icon)
			if err != nil {
				t.Fatalf("validateGroupFields returned error: %v", err)
			}
			if name != tt.wantName || icon != tt.wantIcon {
				t.Fatalf("got (%q, %q), want (%q, %q)", name, icon, tt.wantName, tt.wantIcon)
			}
		})
	}
}

func TestValidateGroupFieldsRejectsStoredXSSPayloads(t *testing.T) {
	tests := []struct {
		name string
		icon string
	}{
		{name: "", icon: "📁"},
		{name: " \t\n ", icon: "📁"},
		{name: `<img src=x onerror="alert(1)">`, icon: "📁"},
		{name: "日常安全巡检", icon: `<svg onload=alert(1)>`},
		{name: "日常安全巡检`onmouseover=alert(1)", icon: "📁"},
		{name: "日常安全巡检\x00", icon: "📁"},
		{name: "日常\n安全巡检", icon: "📁"},
		{name: "日常安全巡检", icon: "📁\x7f"},
		{name: strings.Repeat("分", maxGroupNameRunes+1), icon: "📁"},
		{name: "日常安全巡检", icon: strings.Repeat("📁", maxGroupIconRunes+1)},
	}
	for _, unsafe := range []string{"<", ">", "\"", "'", "`"} {
		tests = append(tests, struct{ name, icon string }{name: "分组" + unsafe, icon: "📁"})
		tests = append(tests, struct{ name, icon string }{name: "分组", icon: unsafe})
	}
	for _, tt := range tests {
		t.Run(tt.name+"/"+tt.icon, func(t *testing.T) {
			if _, _, err := validateGroupFields(tt.name, tt.icon); err == nil {
				t.Fatal("validateGroupFields returned nil error for unsafe input")
			}
		})
	}
}
