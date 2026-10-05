package database

// GetConversationContinuationMetadata reads only the identity/configuration of
// an existing conversation. Unlike list helpers it never hides database errors,
// since doing so could silently continue with a different model or project.
func (db *DB) GetConversationContinuationMetadata(id string) (*Conversation, error) {
	var conv Conversation
	err := db.QueryRow(`SELECT c.id, COALESCE(c.project_id, ''), COALESCE(c.role_name, ''),
		COALESCE(a.ai_channel_id, ''), COALESCE(a.model, '')
		FROM conversations c LEFT JOIN conversation_ai_channels a ON a.conversation_id = c.id
		WHERE c.id = ?`, id).Scan(&conv.ID, &conv.ProjectID, &conv.RoleName, &conv.AIChannelID, &conv.AIModel)
	if err != nil {
		return nil, err
	}
	return &conv, nil
}

// GetFirstConversationUserMessage preserves the exact stored text, including
// targets and whitespace, without loading process details or assistant output.
// sql.ErrNoRows is distinct from a database failure; neither warrants falling
// back to an editable batch task when a conversation is already linked.
func (db *DB) GetFirstConversationUserMessage(conversationID string) (string, error) {
	var message string
	err := db.QueryRow(`SELECT content FROM messages WHERE conversation_id = ? AND role = 'user'
		ORDER BY created_at ASC, id ASC LIMIT 1`, conversationID).Scan(&message)
	return message, err
}
