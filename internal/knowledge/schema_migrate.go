package knowledge

import (
	"fmt"

	"cyberstrike-ai/internal/database"
)

// EnsureKnowledgeEmbeddingsSchema migrates knowledge_embeddings for sub_indexes + embedding metadata.
func EnsureKnowledgeEmbeddingsSchema(db *database.DB) error {
	if db == nil {
		return fmt.Errorf("db is nil")
	}
	// 与 database.initKnowledgeTables / migrateKnowledgeEmbeddingsColumns 对齐
	return db.EnsureKnowledgeSchema()
}

// ensureKnowledgeEmbeddingsSubIndexesColumn 向后兼容；请使用 [EnsureKnowledgeEmbeddingsSchema]。
func ensureKnowledgeEmbeddingsSubIndexesColumn(db *database.DB) error {
	return EnsureKnowledgeEmbeddingsSchema(db)
}
