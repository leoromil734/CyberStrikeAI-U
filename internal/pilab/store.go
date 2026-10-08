package pilab

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
)

func (m *Manager) runPath(id, name string) string {
	return filepath.Join(m.options.Root, "runs", id, name)
}

func (m *Manager) loadLocked() error {
	if m.loaded {
		return nil
	}
	entries, err := os.ReadDir(filepath.Join(m.options.Root, "runs"))
	if os.IsNotExist(err) {
		m.loaded = true
		return nil
	}
	if err != nil || len(entries) > maxRuns {
		return ErrStorage
	}
	loaded := map[string]*storedRun{}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if _, err := uuid.Parse(entry.Name()); err != nil {
			continue
		}
		file, err := os.Open(m.runPath(entry.Name(), "run.json"))
		if os.IsNotExist(err) {
			continue
		} // An interrupted create never published a run.
		if err != nil {
			return ErrStorage
		}
		data, err := io.ReadAll(io.LimitReader(file, 8*1024*1024+1))
		_ = file.Close()
		var run storedRun
		if err != nil || len(data) > 8*1024*1024 || json.Unmarshal(data, &run) != nil || len(data) > runSnapshotLimit(&run.Run) || run.ID != entry.Name() || run.OwnerID == "" || run.EventCount < 0 || run.EventCount > runEventLimit(&run.Run) {
			return ErrStorage
		}
		if active(run.Status) {
			run.Status, run.Error = "interrupted", "上次服务退出时试验未结束；为避免重复请求，不自动恢复执行"
			run.UpdatedAt = time.Now().UTC()
			finishAgents(&run.Run)
			if run.Mode == ModePlatform && m.recoverPlatform != nil {
				if err := m.recoverPlatform(run.OwnerID, &run.Run); err != nil {
					run.Error += "；关联平台状态恢复失败，请检查原项目记录"
				}
			}
			if err := m.saveLocked(&run); err != nil {
				return err
			}
		}
		loaded[run.ID] = &run
	}
	m.runs, m.loaded = loaded, true
	return nil
}

func (m *Manager) saveLocked(run *storedRun) error {
	data, err := json.Marshal(run)
	if err != nil || len(data) > runSnapshotLimit(&run.Run) {
		return ErrStorage
	}
	file, err := os.CreateTemp(m.runPath(run.ID, ""), ".snapshot-*")
	if err != nil {
		return ErrStorage
	}
	name := file.Name()
	defer os.Remove(name)
	if err = file.Chmod(0600); err == nil {
		_, err = file.Write(data)
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		return ErrStorage
	}
	if err := os.Rename(name, m.runPath(run.ID, "run.json")); err != nil {
		return ErrStorage
	}
	return nil
}

func (m *Manager) appendLocked(run *storedRun, event Event) error {
	if run.EventCount >= runEventLimit(&run.Run) {
		return fmt.Errorf("PI 事件预算已耗尽")
	}
	event.Seq, event.Time = run.EventCount+1, time.Now().UTC()
	data, err := json.Marshal(event)
	if err != nil || len(data) > maxEventBytes || run.EventBytes+int64(len(data)+1) > runLogLimit(&run.Run) {
		return fmt.Errorf("PI 事件存储预算已耗尽")
	}
	file, err := os.OpenFile(m.runPath(run.ID, "events.ndjson"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return ErrStorage
	}
	_, err = file.Write(append(data, '\n'))
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		return ErrStorage
	}
	run.EventCount = event.Seq
	run.EventBytes += int64(len(data) + 1)
	run.UpdatedAt = event.Time
	return m.saveLocked(run)
}

func (m *Manager) Events(owner, id string, after int64) (EventPage, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	run, err := m.ownedLocked(owner, id)
	if err != nil {
		return EventPage{}, err
	}
	if after < 0 || after > run.EventCount {
		return EventPage{}, fmt.Errorf("事件游标超出有效范围")
	}
	result := EventPage{Events: []Event{}, Cursor: after}
	if after == run.EventCount {
		return result, nil
	}
	file, err := os.Open(m.runPath(id, "events.ndjson"))
	if err != nil {
		return result, ErrStorage
	}
	defer file.Close()
	scanner := bufio.NewScanner(io.LimitReader(file, runLogLimit(&run.Run)+1))
	scanner.Buffer(make([]byte, 4096), maxEventBytes)
	for scanner.Scan() {
		var event Event
		if json.Unmarshal(scanner.Bytes(), &event) != nil {
			return result, ErrStorage
		}
		if event.Seq <= after {
			continue
		}
		if event.Seq > run.EventCount {
			break
		} // Ignore an unpublished tail after a failed snapshot.
		if event.Seq != result.Cursor+1 {
			return result, ErrStorage
		}
		result.Events = append(result.Events, event)
		result.Cursor = event.Seq
		if len(result.Events) == 100 {
			break
		}
	}
	if scanner.Err() != nil {
		return result, ErrStorage
	}
	if len(result.Events) == 0 && after < run.EventCount {
		return result, ErrStorage
	}
	result.HasMore = result.Cursor < run.EventCount
	return result, nil
}
