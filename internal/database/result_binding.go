package database

// ExecutionBoundProject is an internal MCP storage seam. The triple must match
// a start-time metadata record; a later conversation rebind cannot relocate the
// original files or import them into a new project.
func (db *DB) ExecutionBoundProject(id, conversationID, owner string) (string, error) {
	var project string
	err := db.QueryRow(`SELECT project_id FROM result_execution_metadata WHERE execution_id=? AND conversation_id=? AND owner=?`, id, conversationID, owner).Scan(&project)
	return project, err
}
