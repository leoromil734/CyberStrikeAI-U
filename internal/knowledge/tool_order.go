package knowledge

// knowledgeItemGroup preserves final retrieval order across documents. Vector
// similarity is display metadata, not a replacement for the reranker's order.
type knowledgeItemGroup struct {
	itemID  string
	results []*RetrievalResult
}

func groupKnowledgeResultsInOrder(results []*RetrievalResult) []*knowledgeItemGroup {
	groups := make([]*knowledgeItemGroup, 0)
	byID := make(map[string]*knowledgeItemGroup)
	for _, result := range results {
		if result == nil || result.Item == nil || result.Chunk == nil {
			continue
		}
		group := byID[result.Item.ID]
		if group == nil {
			group = &knowledgeItemGroup{itemID: result.Item.ID}
			byID[result.Item.ID] = group
			groups = append(groups, group)
		}
		group.results = append(group.results, result)
	}
	return groups
}
