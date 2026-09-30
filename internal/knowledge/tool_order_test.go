package knowledge

import "testing"

func TestKnowledgeToolGroupingPreservesFinalRankNotVectorScore(t *testing.T) {
	result := func(item string, chunk int, score float64) *RetrievalResult {
		return &RetrievalResult{Item: &KnowledgeItem{ID: item}, Chunk: &KnowledgeChunk{ChunkIndex: chunk}, Score: score}
	}
	// The reranker has promoted low-vector-score B before A. A later B chunk
	// has a higher vector score but must not become the primary match.
	first := result("b", 3, 0.3)
	groups := groupKnowledgeResultsInOrder([]*RetrievalResult{first, result("a", 1, 0.9), result("b", 2, 0.99), nil, {}})
	if len(groups) != 2 || groups[0].itemID != "b" || groups[1].itemID != "a" {
		t.Fatalf("final order lost: %+v", groups)
	}
	if groups[0].results[0] != first || len(groups[0].results) != 2 {
		t.Fatal("document primary match lost its final relevance rank")
	}
}
