package openai

// SSEAccumulatedKey 为 SSE progress 事件 data 中可选的服务端权威全文快照。
// 有快照时覆盖 buffer；带 streamSeq 的无快照帧按连续序号追加纯增量。
const SSEAccumulatedKey = "accumulated"

// WithSSEAccumulated 在 progress data 中附带当前流式累计全文（权威快照）。
func WithSSEAccumulated(data map[string]interface{}, accumulated string) map[string]interface{} {
	if data == nil {
		data = make(map[string]interface{}, 1)
	}
	data[SSEAccumulatedKey] = accumulated
	return data
}

// NormalizeStreamingDelta 将可能是“累计片段/重发片段”的内容归一化为“纯增量”。
// 与 unexported normalizeStreamingDelta 相同，供 agent / multiagent 等包在发 SSE 前累计正文。
func NormalizeStreamingDelta(current, incoming string) (next, delta string) {
	return normalizeStreamingDelta(current, incoming)
}
