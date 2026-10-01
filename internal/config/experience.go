package config

// ExperienceConfig controls cross-task memory. Learning only creates private
// candidates; review and sharing always require explicit platform permissions.
// Settings take effect at application startup.
type ExperienceConfig struct {
	Disabled          bool `yaml:"disabled,omitempty" json:"disabled"`
	AutoLearnDisabled bool `yaml:"auto_learn_disabled,omitempty" json:"auto_learn_disabled"`
}
