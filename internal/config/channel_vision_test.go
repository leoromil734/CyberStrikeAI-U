package config

import (
	"testing"

	"gopkg.in/yaml.v3"
)

func TestResolveAIVisionPreservesLegacyAndExplicitOverrides(t *testing.T) {
	cfg := Config{Vision: VisionConfig{Enabled: true, Model: "legacy-vision"}, AI: AIConfig{DefaultChannel: "custom", Channels: map[string]AIChannelConfig{
		"inherited": {Model: "text-a"},
		"custom":    {Model: "text-b", Vision: &VisionConfig{Enabled: true, Model: "vision-b", BaseURL: "https://example.invalid/v1"}},
		"disabled":  {Vision: &VisionConfig{Enabled: false}},
	}}}
	if cfg.ResolveAIVision("inherited").Model != "legacy-vision" || cfg.ResolveAIVision("").Model != "vision-b" || cfg.ResolveAIVision("disabled").Enabled {
		t.Fatal("incorrect vision inheritance")
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var loaded Config
	if err = yaml.Unmarshal(data, &loaded); err != nil {
		t.Fatal(err)
	}
	if loaded.AI.Channels["inherited"].Vision != nil || loaded.AI.Channels["disabled"].Vision == nil || loaded.ResolveAIVision("").Model != "vision-b" {
		t.Fatal("vision overrides did not survive configuration persistence")
	}
}
