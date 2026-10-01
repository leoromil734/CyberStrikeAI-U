package database

import (
	"strings"
	"testing"
)

func batchProjectOwner(t *testing.T, db *DB) string {
	t.Helper()
	user, err := db.CreateRBACUser("queue-owner", "Queue owner", "test-hash", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	return user.ID
}

func privateBatchTasks(messages ...string) ([]map[string]interface{}, []*Project) {
	tasks := make([]map[string]interface{}, 0, len(messages))
	projects := make([]*Project, 0, len(messages))
	for _, message := range messages {
		project := NewBatchTaskProject(message)
		projects = append(projects, project)
		tasks = append(tasks, map[string]interface{}{"id": project.ID + "-task", "message": message, "project": project, "aiChannelId": ""})
	}
	return tasks, projects
}

func TestBatchQueueIndependentProjectsAreAtomicOwnedAndDistinct(t *testing.T) {
	db := newRBACTestDB(t)
	owner := batchProjectOwner(t, db)
	tasks, projects := privateBatchTasks("对 example.com 做专项验证", "复测 example.com", "测试 api.other.example.com")
	err := db.CreateBatchQueue("private-queue", "isolated", "", "deep", "manual", "", nil, "", 3, 0, tasks,
		BatchQueueCreateOptions{IndependentProjects: true, OwnerUserID: owner})
	if err != nil {
		t.Fatal(err)
	}
	queue, err := db.GetBatchQueue("private-queue")
	if err != nil || queue == nil || queue.IndependentProjects.Int64 != 1 || queue.ProjectID.Valid {
		t.Fatalf("private mode was not persisted: %v %+v", err, queue)
	}
	stored, err := db.GetBatchTasks(queue.ID)
	if err != nil || len(stored) != len(tasks) {
		t.Fatalf("missing tasks: %v %+v", err, stored)
	}
	ids, names := map[string]bool{}, map[string]bool{}
	for i, task := range stored {
		if !task.ProjectID.Valid || task.ProjectID.String != projects[i].ID || ids[task.ProjectID.String] {
			t.Fatalf("tasks shared/lost a private project: %+v", stored)
		}
		ids[task.ProjectID.String] = true
		project, err := db.GetProject(task.ProjectID.String)
		if err != nil || project.Name != projects[i].Name || names[project.Name] || !strings.Contains(project.Name, "example.com-") {
			t.Fatalf("incorrect target/random project name: err=%v project=%+v", err, project)
		}
		names[project.Name] = true
		if project.ScopeJSON != "" {
			t.Fatal("normalized display target was turned into a broader authorization scope")
		}
		if db.GetResourceOwner("project", project.ID) != owner || !db.UserCanAccessResource(owner, RBACScopeAssigned, "project", project.ID) || db.UserCanAccessResource("another-user", RBACScopeAssigned, "project", project.ID) {
			t.Fatalf("private project ownership/access was not preserved: %+v", project)
		}
	}
	hits, err := db.CheckTargetRuns([]string{"example.com"})
	if err != nil || len(hits) != 1 || hits[0].RunCount != 0 || hits[0].SubmittedCount != 2 {
		t.Fatalf("created tasks must be discoverable without claiming execution: %v %+v", err, hits)
	}
}

func TestBatchQueueProjectCreationRollsBackWithTaskFailure(t *testing.T) {
	db := newRBACTestDB(t)
	owner := batchProjectOwner(t, db)
	if _, err := db.Exec(`CREATE TRIGGER reject_private_task BEFORE INSERT ON batch_tasks
		WHEN NEW.message = 'reject example.com' BEGIN SELECT RAISE(ABORT, 'injected task failure'); END`); err != nil {
		t.Fatal(err)
	}
	tasks, projects := privateBatchTasks("first example.com", "reject example.com")
	if err := db.CreateBatchQueue("rollback-private", "", "", "eino_single", "manual", "", nil, "", 1, 0, tasks,
		BatchQueueCreateOptions{IndependentProjects: true, OwnerUserID: owner}); err == nil {
		t.Fatal("injected task failure was accepted")
	}
	if queue, err := db.GetBatchQueue("rollback-private"); err != nil || queue != nil {
		t.Fatalf("partial queue survived rollback: %v %+v", err, queue)
	}
	for _, project := range projects {
		if _, err := db.GetProject(project.ID); err == nil {
			t.Fatal("orphan private project survived rollback")
		}
	}
	if hits, err := db.CheckTargetRuns([]string{"example.com"}); err != nil || len(hits) != 0 {
		t.Fatalf("rolled-back task polluted target history: %v %+v", err, hits)
	}
}

func TestBatchPrivateAppendAndEditRetainPriorFacts(t *testing.T) {
	db := newRBACTestDB(t)
	owner := batchProjectOwner(t, db)
	tasks, originalProjects := privateBatchTasks("test first.example.com")
	if err := db.CreateBatchQueue("edit-private", "", "", "eino_single", "manual", "", nil, "", 1, 0, tasks,
		BatchQueueCreateOptions{IndependentProjects: true, OwnerUserID: owner}); err != nil {
		t.Fatal(err)
	}
	old := originalProjects[0]
	if _, err := db.UpsertProjectFact(&ProjectFact{ProjectID: old.ID, FactKey: "target/primary", Summary: "prior target", Body: "original facts", Confidence: "confirmed"}); err != nil {
		t.Fatal(err)
	}
	added := NewBatchTaskProject("test second.example.com")
	if err := db.AddBatchTaskWithProject("edit-private", "added-task", "test second.example.com", "channel", added); err != nil {
		t.Fatal(err)
	}
	replacement := NewBatchTaskProject("test third.example.com")
	if err := db.UpdateBatchTaskMessageWithProject("edit-private", tasks[0]["id"].(string), "test third.example.com", replacement); err != nil {
		t.Fatal(err)
	}
	rows, err := db.GetBatchTasks("edit-private")
	if err != nil || len(rows) != 2 || rows[0].ProjectID.String != replacement.ID || rows[1].ProjectID.String != added.ID {
		t.Fatalf("append/edit did not persist distinct projects: %v %+v", err, rows)
	}
	if oldFact, err := db.GetProjectFactByKey(old.ID, "target/primary"); err != nil || oldFact.Body != "original facts" {
		t.Fatalf("editing moved or rewrote old evidence: %v %+v", err, oldFact)
	}
	if _, err := db.GetProjectFactByKey(replacement.ID, "target/primary"); err == nil {
		t.Fatal("replacement project inherited prior target facts")
	}
	if db.GetResourceOwner("project", replacement.ID) != owner || db.GetResourceOwner("project", added.ID) != owner {
		t.Fatal("append/edit lost project ownership")
	}
}

func TestBatchPrivateModeRejectsSharedBinding(t *testing.T) {
	db := newRBACTestDB(t)
	if err := db.CreateBatchQueue("invalid-mixed", "", "", "eino_single", "manual", "", nil, "shared-project", 1, 0, nil,
		BatchQueueCreateOptions{IndependentProjects: true}); err == nil {
		t.Fatal("private mode silently used a shared project")
	}
}
