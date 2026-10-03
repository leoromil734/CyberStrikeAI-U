package database

import (
	"encoding/json"
	"time"
)

// AIChannelProbe contains no credentials or response content. TTFT measures the
// first non-empty streamed text delta; nil means no text token was received.
type AIChannelProbe struct {
	ChannelID   string    `json:"channel_id"`
	ChannelName string    `json:"channel_name"`
	Model       string    `json:"model"`
	Status      string    `json:"status"`
	Success     bool      `json:"success"`
	TTFTMs      *int64    `json:"ttft_ms"`
	LatencyMs   int64     `json:"latency_ms"`
	TestedAt    time.Time `json:"tested_at"`
	Error       string    `json:"error,omitempty"`
	Stale       bool      `json:"stale"`
	ConfigHash  string    `json:"-"`
}

func (db *DB) SaveAIChannelProbe(probe AIChannelProbe) error {
	body, err := json.Marshal(probe)
	if err != nil {
		return err
	}
	_, err = db.Exec(`INSERT INTO ai_channel_probes (channel_id, config_hash, result_json, tested_at) VALUES (?, ?, ?, ?)
		ON CONFLICT(channel_id) DO UPDATE SET config_hash=excluded.config_hash, result_json=excluded.result_json, tested_at=excluded.tested_at
		WHERE excluded.tested_at >= ai_channel_probes.tested_at`, probe.ChannelID, probe.ConfigHash, string(body), probe.TestedAt)
	return err
}

func (db *DB) ListAIChannelProbes() (map[string]AIChannelProbe, error) {
	rows, err := db.Query(`SELECT channel_id, config_hash, result_json FROM ai_channel_probes`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]AIChannelProbe)
	for rows.Next() {
		var id, hash, body string
		if err := rows.Scan(&id, &hash, &body); err != nil {
			return nil, err
		}
		var result AIChannelProbe
		if err := json.Unmarshal([]byte(body), &result); err != nil {
			return nil, err
		}
		result.ConfigHash = hash
		out[id] = result
	}
	return out, rows.Err()
}
