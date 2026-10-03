package database

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"golang.org/x/net/idna"
)

// Asset is a persistent, deduplicated target discovered manually or by recon providers.
type Asset struct {
	ID                     string     `json:"id"`
	ProjectID              string     `json:"project_id,omitempty"`
	ProjectName            string     `json:"project_name,omitempty"`
	Host                   string     `json:"host"`
	IP                     string     `json:"ip"`
	Port                   int        `json:"port"`
	Domain                 string     `json:"domain"`
	Protocol               string     `json:"protocol"`
	Title                  string     `json:"title"`
	Server                 string     `json:"server"`
	Country                string     `json:"country"`
	Province               string     `json:"province"`
	City                   string     `json:"city"`
	ResponsiblePerson      string     `json:"responsible_person"`
	Department             string     `json:"department"`
	BusinessSystem         string     `json:"business_system"`
	Environment            string     `json:"environment"`
	Criticality            string     `json:"criticality"`
	Source                 string     `json:"source"`
	SourceQuery            string     `json:"source_query"`
	Status                 string     `json:"status"`
	Tags                   []string   `json:"tags"`
	FirstSeenAt            time.Time  `json:"first_seen_at"`
	LastSeenAt             time.Time  `json:"last_seen_at"`
	CreatedAt              time.Time  `json:"created_at"`
	UpdatedAt              time.Time  `json:"updated_at"`
	LastScanAt             *time.Time `json:"last_scan_at,omitempty"`
	LastScanConversationID string     `json:"last_scan_conversation_id,omitempty"`
	LastScanQueueID        string     `json:"last_scan_queue_id,omitempty"`
	LastScanTaskID         string     `json:"last_scan_task_id,omitempty"`
	VulnerabilityCount     int        `json:"vulnerability_count"`
	RiskLevel              string     `json:"risk_level"`
	OwnerUserID            string     `json:"-"`
	// Optional observation metadata. Identity/IP/source are always taken from
	// this Asset, not from caller-supplied observation identity fields.
	Observation *AssetObservation `json:"observation,omitempty"`
}

type AssetListFilter struct {
	Search             string
	Status             string
	Protocol           string
	ProjectID          string
	Source             string
	Tag                string
	Host               string
	IP                 string
	Domain             string
	Port               *int
	RiskLevel          string
	MinVulnerabilities *int
	MaxVulnerabilities *int
	Country            string
	Province           string
	City               string
	ResponsiblePerson  string
	Department         string
	BusinessSystem     string
	Environment        string
	Criticality        string
	ScanState          string
	ScanOverdueDays    *int
	LastScanBefore     *time.Time
	LastScanAfter      *time.Time
	FirstSeenBefore    *time.Time
	FirstSeenAfter     *time.Time
	LastSeenBefore     *time.Time
	LastSeenAfter      *time.Time
	SortBy             string
	SortOrder          string
}

type AssetImportResult struct {
	Created int `json:"created"`
	Updated int `json:"updated"`
	Skipped int `json:"skipped"`
}

func normalizeAsset(a *Asset) {
	a.Host = strings.TrimSpace(a.Host)
	a.IP = strings.ToLower(strings.TrimSpace(a.IP))
	a.Domain = strings.ToLower(strings.TrimSpace(a.Domain))
	a.Protocol = strings.ToLower(strings.TrimSpace(a.Protocol))
	a.Title = strings.TrimSpace(a.Title)
	a.Server = strings.TrimSpace(a.Server)
	a.Country = strings.TrimSpace(a.Country)
	a.Province = strings.TrimSpace(a.Province)
	a.City = strings.TrimSpace(a.City)
	a.ResponsiblePerson = strings.TrimSpace(a.ResponsiblePerson)
	a.Department = strings.TrimSpace(a.Department)
	a.BusinessSystem = strings.TrimSpace(a.BusinessSystem)
	a.Environment = strings.ToLower(strings.TrimSpace(a.Environment))
	a.Criticality = strings.ToLower(strings.TrimSpace(a.Criticality))
	a.Source = strings.TrimSpace(a.Source)
	a.SourceQuery = strings.TrimSpace(a.SourceQuery)
	a.ProjectID = strings.TrimSpace(a.ProjectID)
	a.Status = strings.ToLower(strings.TrimSpace(a.Status))
	if a.Status == "" {
		a.Status = "active"
	}
	if a.Source == "" {
		a.Source = "manual"
	}
	seen := map[string]bool{}
	tags := make([]string, 0, len(a.Tags))
	for _, tag := range a.Tags {
		tag = strings.TrimSpace(tag)
		if tag != "" && !seen[tag] {
			seen[tag] = true
			tags = append(tags, tag)
		}
	}
	a.Tags = tags
	// URL 型 Host 是常见输入。缺失的结构化字段在服务端同样补齐，确保
	// API、MCP 与 Web 端产生一致的去重键，而不依赖某个客户端正确解析。
	if strings.Contains(a.Host, "://") {
		if parsed, err := url.Parse(a.Host); err == nil && parsed.Hostname() != "" && parsed.User == nil {
			hostname := strings.Trim(strings.ToLower(parsed.Hostname()), "[]")
			if net.ParseIP(hostname) != nil && a.IP == "" {
				a.IP = hostname
			} else if a.Domain == "" {
				if ascii, err := idna.Lookup.ToASCII(hostname); err == nil {
					a.Domain = strings.ToLower(ascii)
				}
			}
			if a.Protocol == "" {
				a.Protocol = strings.ToLower(parsed.Scheme)
			}
			if a.Port == 0 {
				if parsed.Port() != "" {
					a.Port, _ = strconv.Atoi(parsed.Port())
				} else if a.Protocol == "https" {
					a.Port = 443
				} else if a.Protocol == "http" {
					a.Port = 80
				}
			}
		}
	}
	// Recon providers occasionally return placeholders, multiple values, or
	// provider-specific identifiers in structured fields. They are optional
	// enrichment; a valid Host must not make the entire batch fail because one
	// of those fields is dirty.
	if strings.EqualFold(a.Source, "fofa") {
		if a.IP != "" && net.ParseIP(strings.Trim(a.IP, "[]")) == nil {
			a.IP = ""
		}
		if a.Domain != "" {
			ascii, err := idna.Lookup.ToASCII(strings.TrimSuffix(a.Domain, "."))
			if err != nil || !validAssetDomain(ascii) {
				a.Domain = ""
			} else {
				a.Domain = strings.ToLower(ascii)
			}
		}
		if a.Protocol != "" && !assetProtocolPattern.MatchString(a.Protocol) {
			a.Protocol = ""
		}
	}
}

var assetProtocolPattern = regexp.MustCompile(`^[a-z][a-z0-9+.-]{0,31}$`)

// AssetValidationError distinguishes user-correctable asset data from storage failures.
type AssetValidationError struct{ Message string }

func (e *AssetValidationError) Error() string { return e.Message }

func assetValidationErrorf(format string, args ...interface{}) error {
	return &AssetValidationError{Message: fmt.Sprintf(format, args...)}
}

func validateAsset(a *Asset) error {
	if a == nil {
		return assetValidationErrorf("资产不能为空")
	}
	if a.Host == "" && a.IP == "" && a.Domain == "" {
		return assetValidationErrorf("资产目标不能为空")
	}
	if a.Port < 0 || a.Port > 65535 {
		return assetValidationErrorf("端口必须在 0-65535 之间")
	}
	if a.IP != "" && net.ParseIP(strings.Trim(a.IP, "[]")) == nil {
		return assetValidationErrorf("IP 地址格式无效")
	}
	if a.Domain != "" {
		ascii, err := idna.Lookup.ToASCII(strings.TrimSuffix(a.Domain, "."))
		if err != nil || !validAssetDomain(ascii) {
			return assetValidationErrorf("域名格式无效")
		}
		a.Domain = strings.ToLower(ascii)
	}
	if a.Protocol != "" && !assetProtocolPattern.MatchString(a.Protocol) {
		return assetValidationErrorf("协议格式无效")
	}
	if a.Status != "active" && a.Status != "inactive" {
		return assetValidationErrorf("资产状态必须为 active 或 inactive")
	}
	for name, value := range map[string]string{
		"Host": a.Host, "域名": a.Domain, "协议": a.Protocol, "页面标题": a.Title,
		"服务指纹": a.Server, "国家/地区": a.Country, "省份/州": a.Province, "城市": a.City,
		"负责人": a.ResponsiblePerson, "部门": a.Department, "业务系统": a.BusinessSystem,
	} {
		limit := 255
		if name == "Host" || name == "页面标题" {
			limit = 500
		}
		if utf8.RuneCountInString(value) > limit {
			return assetValidationErrorf("%s不能超过 %d 个字符", name, limit)
		}
	}
	if !oneOfAssetValue(a.Environment, "", "production", "staging", "testing", "development", "other") {
		return assetValidationErrorf("环境必须为 production、staging、testing、development 或 other")
	}
	if !oneOfAssetValue(a.Criticality, "", "critical", "high", "medium", "low") {
		return assetValidationErrorf("重要性必须为 critical、high、medium 或 low")
	}
	if len(a.Tags) > 30 {
		return assetValidationErrorf("标签不能超过 30 个")
	}
	for _, tag := range a.Tags {
		if utf8.RuneCountInString(tag) > 64 {
			return assetValidationErrorf("单个标签不能超过 64 个字符")
		}
	}
	return nil
}

func oneOfAssetValue(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}

func validAssetDomain(domain string) bool {
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if domain == "" || len(domain) > 253 || net.ParseIP(domain) != nil {
		return false
	}
	for _, label := range strings.Split(domain, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return false
			}
		}
	}
	return true
}

func assetDedupKey(a *Asset) string {
	target := a.Domain
	if target == "" {
		target = a.IP
	}
	if target == "" {
		target = strings.ToLower(a.Host)
	}
	return strings.Join([]string{target, strconv.Itoa(a.Port), a.Protocol}, "|")
}

func appendAssetAccess(query string, args []interface{}, access RBACListAccess, alias string) (string, []interface{}) {
	if strings.TrimSpace(access.UserID) == "" || access.Scope == RBACScopeAll {
		return query, args
	}
	prefix := ""
	if alias != "" {
		prefix = alias + "."
	}
	query += ` AND (` + prefix + `owner_user_id = ? OR EXISTS (
		SELECT 1 FROM rbac_resource_assignments ra
		WHERE ra.user_id = ? AND ra.resource_type = 'asset' AND ra.resource_id = ` + prefix + `id
	) OR (` + prefix + `project_id IS NOT NULL AND ` + prefix + `project_id <> '' AND (
		EXISTS (SELECT 1 FROM projects ap WHERE ap.id=` + prefix + `project_id AND ap.owner_user_id=?)
		OR EXISTS (SELECT 1 FROM rbac_resource_assignments pra WHERE pra.user_id=? AND pra.resource_type='project' AND pra.resource_id=` + prefix + `project_id)
	)))`
	return query, append(args, access.UserID, access.UserID, access.UserID, access.UserID)
}

const assetInsertSQL = `INSERT INTO assets (
	id,dedup_key,project_id,host,ip,port,domain,protocol,title,server,country,province,city,source,source_query,status,tags_json,
	responsible_person,department,business_system,environment,criticality,
	first_seen_at,last_seen_at,created_at,updated_at,owner_user_id
) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT (dedup_key) DO NOTHING`

func (db *DB) UpsertAssets(assets []*Asset, ownerUserID string, allowGlobal ...bool) (AssetImportResult, error) {
	ownerUserID = strings.TrimSpace(ownerUserID)
	global := len(allowGlobal) > 0 && allowGlobal[0]
	access := RBACListAccess{UserID: ownerUserID, Scope: RBACScopeOwn}
	if global {
		access.Scope = RBACScopeAll
	}
	type candidate struct {
		index int
		asset Asset
		key   string
	}
	candidates := make([]candidate, 0, len(assets))
	nilCount := 0
	for i, asset := range assets {
		if asset == nil {
			nilCount++
			continue
		}
		// Do not expose generated IDs or partial successes before COMMIT, and
		// start every transaction retry with the same normalized input.
		copy := *asset
		copy.Tags = append([]string(nil), asset.Tags...)
		if asset.Observation != nil {
			observation := *asset.Observation
			copy.Observation = &observation
		}
		normalizeAsset(&copy)
		if err := validateAsset(&copy); err != nil {
			return AssetImportResult{}, fmt.Errorf("第 %d 个资产无效: %w", i+1, err)
		}
		candidates = append(candidates, candidate{index: i, asset: copy, key: assetDedupKey(&copy)})
	}
	// A consistent lock order avoids opposite-order batch deadlocks in PG.
	sort.SliceStable(candidates, func(i, j int) bool { return candidates[i].key < candidates[j].key })
	var result AssetImportResult
	committed := make([]Asset, len(candidates))
	err := db.withAssetTransaction(func(tx *Tx) error {
		result = AssetImportResult{Skipped: nilCount}
		now := time.Now().UTC()
		for i, input := range candidates {
			a := input.asset
			a.ID = ""
			committed[i] = a
			tagsJSON, _ := json.Marshal(a.Tags)
			newID := uuid.NewString()
			// SQLite obtains its write reservation before any read. PG waits on
			// the unique key here, then reads/locks the winning row below. The
			// conflict clause is intentionally not allowed to mutate metadata.
			insert, err := tx.Exec(assetInsertSQL,
				newID, input.key, nullIfEmpty(a.ProjectID), a.Host, a.IP, a.Port, a.Domain, a.Protocol, a.Title, a.Server,
				a.Country, a.Province, a.City, a.Source, a.SourceQuery, a.Status, string(tagsJSON),
				a.ResponsiblePerson, a.Department, a.BusinessSystem, a.Environment, a.Criticality,
				now, now, now, now, nullIfEmpty(ownerUserID))
			if err != nil {
				return fmt.Errorf("创建资产失败: %w", err)
			}
			inserted, err := insert.RowsAffected()
			if err != nil {
				return err
			}
			var existingID, existingOwner, existingProject string
			if err := tx.QueryRow(`SELECT id,COALESCE(owner_user_id,''),COALESCE(project_id,''),first_seen_at,created_at
				FROM assets WHERE dedup_key=?`+db.assetRowLock(), input.key).Scan(
				&existingID, &existingOwner, &existingProject, &a.FirstSeenAt, &a.CreatedAt); err != nil {
				return fmt.Errorf("检查资产去重键失败: %w", err)
			}
			if inserted == 0 && !global {
				// Preserve the import/upsert owner's strict write boundary even
				// when an asset is explicitly assigned to another user for read.
				if existingOwner != "" && strings.TrimSpace(existingOwner) != ownerUserID {
					result.Skipped++
					continue
				}
				// Ownerless legacy rows bound to a private project are not public.
				if existingOwner == "" && existingProject != "" && ownerUserID != "" {
					query, args := appendAssetAccess("SELECT COUNT(*) FROM assets WHERE id=?", []interface{}{existingID}, access, "assets")
					var n int
					if err := tx.QueryRow(query, args...).Scan(&n); err != nil {
						return err
					}
					if n != 1 {
						result.Skipped++
						continue
					}
				}
			}
			if err := checkAssetProjectAccess(tx, a.ProjectID, access); err != nil {
				return err
			}
			if inserted == 0 {
				_, err = tx.Exec(`UPDATE assets SET
					host=CASE WHEN ?<>'' THEN ? ELSE host END, ip=CASE WHEN ip='' THEN ? ELSE ip END,
					domain=CASE WHEN ?<>'' THEN ? ELSE domain END, protocol=CASE WHEN ?<>'' THEN ? ELSE protocol END,
					title=CASE WHEN ?<>'' THEN ? ELSE title END, server=CASE WHEN ?<>'' THEN ? ELSE server END,
					country=CASE WHEN ?<>'' THEN ? ELSE country END, province=CASE WHEN ?<>'' THEN ? ELSE province END,
					city=CASE WHEN ?<>'' THEN ? ELSE city END, source=CASE WHEN ?<>'' THEN ? ELSE source END,
					source_query=CASE WHEN ?<>'' THEN ? ELSE source_query END,
					project_id=CASE WHEN COALESCE(project_id,'')='' AND ?<>'' THEN ? ELSE project_id END,
					responsible_person=CASE WHEN ?<>'' THEN ? ELSE responsible_person END,
					department=CASE WHEN ?<>'' THEN ? ELSE department END,
					business_system=CASE WHEN ?<>'' THEN ? ELSE business_system END,
					environment=CASE WHEN ?<>'' THEN ? ELSE environment END,
					criticality=CASE WHEN ?<>'' THEN ? ELSE criticality END,
					tags_json=CASE WHEN ?<>'[]' THEN ? ELSE tags_json END,
					last_seen_at=?, updated_at=? WHERE id=?`,
					a.Host, a.Host, a.IP, a.Domain, a.Domain, a.Protocol, a.Protocol,
					a.Title, a.Title, a.Server, a.Server, a.Country, a.Country, a.Province, a.Province,
					a.City, a.City, a.Source, a.Source, a.SourceQuery, a.SourceQuery, a.ProjectID, nullIfEmpty(a.ProjectID),
					a.ResponsiblePerson, a.ResponsiblePerson, a.Department, a.Department, a.BusinessSystem, a.BusinessSystem,
					a.Environment, a.Environment, a.Criticality, a.Criticality, string(tagsJSON), string(tagsJSON),
					now, now, existingID)
				if err != nil {
					return fmt.Errorf("更新资产失败: %w", err)
				}
			}
			if err := linkAssetProject(tx, existingID, a.ProjectID, now); err != nil {
				return fmt.Errorf("关联资产项目失败: %w", err)
			}
			if err := appendAssetObservation(tx, existingID, &a, now); err != nil {
				return fmt.Errorf("保存资产观测失败: %w", err)
			}
			if ownerUserID != "" && (inserted == 1 || existingOwner == "" || strings.TrimSpace(existingOwner) == ownerUserID) {
				if _, err := tx.Exec(`INSERT INTO rbac_resource_assignments (id,user_id,resource_type,resource_id,created_at)
					SELECT ?,id,?,?,? FROM rbac_users WHERE id=? ON CONFLICT (user_id,resource_type,resource_id) DO NOTHING`,
					uuid.NewString(), "asset", existingID, now, ownerUserID); err != nil {
					return fmt.Errorf("授权资产失败: %w", err)
				}
			}
			a.ID, a.LastSeenAt, a.UpdatedAt = existingID, now, now
			committed[i] = a
			if inserted == 1 {
				result.Created++
			} else {
				result.Updated++
			}
		}
		return nil
	})
	if err != nil {
		return AssetImportResult{}, err
	}
	for i, input := range candidates {
		*assets[input.index] = committed[i]
	}
	return result, nil
}

func assetWhere(filter AssetListFilter, access RBACListAccess) (string, []interface{}) {
	query := " WHERE 1=1"
	args := []interface{}{}
	if q := strings.TrimSpace(filter.Search); q != "" {
		pattern := "%" + escapeAssetLike(strings.ToLower(q)) + "%"
		query += ` AND (LOWER(assets.host) LIKE ? ESCAPE '\' OR LOWER(assets.ip) LIKE ? ESCAPE '\' OR LOWER(assets.domain) LIKE ? ESCAPE '\'
			OR LOWER(assets.title) LIKE ? ESCAPE '\' OR LOWER(assets.server) LIKE ? ESCAPE '\' OR LOWER(assets.tags_json) LIKE ? ESCAPE '\'
			OR LOWER(assets.responsible_person) LIKE ? ESCAPE '\' OR LOWER(assets.department) LIKE ? ESCAPE '\' OR LOWER(assets.business_system) LIKE ? ESCAPE '\'
			OR EXISTS (SELECT 1 FROM asset_observations o WHERE o.asset_id=assets.id AND LOWER(o.ip) LIKE ? ESCAPE '\'))`
		for i := 0; i < 10; i++ {
			args = append(args, pattern)
		}
	}
	if filter.Status != "" {
		query += " AND assets.status = ?"
		args = append(args, filter.Status)
	}
	if filter.Protocol != "" {
		query += " AND assets.protocol = ?"
		args = append(args, filter.Protocol)
	}
	query, args = appendAssetProjectScope(query, args, filter.ProjectID)
	if filter.Source != "" {
		query += ` AND (LOWER(assets.source) = LOWER(?) OR EXISTS (
			SELECT 1 FROM asset_observations o WHERE o.asset_id=assets.id AND LOWER(o.source)=LOWER(?)
		))`
		args = append(args, strings.TrimSpace(filter.Source), strings.TrimSpace(filter.Source))
	}
	if tag := strings.TrimSpace(filter.Tag); tag != "" {
		pattern := "%\"" + escapeAssetLike(strings.ToLower(tag)) + "\"%"
		query += ` AND LOWER(assets.tags_json) LIKE ? ESCAPE '\'`
		args = append(args, pattern)
	}
	if filter.Host != "" {
		query += " AND LOWER(assets.host) = LOWER(?)"
		args = append(args, strings.TrimSpace(filter.Host))
	}
	if filter.IP != "" {
		query += ` AND (LOWER(assets.ip) = LOWER(?) OR EXISTS (
			SELECT 1 FROM asset_observations o WHERE o.asset_id=assets.id AND LOWER(o.ip)=LOWER(?)
		))`
		args = append(args, strings.TrimSpace(filter.IP), strings.TrimSpace(filter.IP))
	}
	if filter.Domain != "" {
		query += " AND LOWER(assets.domain) = LOWER(?)"
		args = append(args, strings.TrimSpace(filter.Domain))
	}
	if filter.Port != nil {
		query += " AND assets.port = ?"
		args = append(args, *filter.Port)
	}
	if filter.RiskLevel != "" {
		query += " AND " + assetRiskLevelExpr + " = ?"
		args = append(args, strings.ToLower(strings.TrimSpace(filter.RiskLevel)))
	}
	if filter.MinVulnerabilities != nil {
		query += " AND " + assetVulnerabilityCountExpr + " >= ?"
		args = append(args, *filter.MinVulnerabilities)
	}
	if filter.MaxVulnerabilities != nil {
		query += " AND " + assetVulnerabilityCountExpr + " <= ?"
		args = append(args, *filter.MaxVulnerabilities)
	}
	for _, item := range []struct {
		column string
		value  string
	}{
		{"assets.country", filter.Country}, {"assets.province", filter.Province}, {"assets.city", filter.City},
		{"assets.responsible_person", filter.ResponsiblePerson}, {"assets.department", filter.Department},
		{"assets.business_system", filter.BusinessSystem}, {"assets.environment", filter.Environment}, {"assets.criticality", filter.Criticality},
	} {
		if strings.TrimSpace(item.value) != "" {
			query += " AND LOWER(" + item.column + ") = LOWER(?)"
			args = append(args, strings.TrimSpace(item.value))
		}
	}
	switch strings.ToLower(strings.TrimSpace(filter.ScanState)) {
	case "never":
		query += " AND " + assetEffectiveLastScanExpr + " IS NULL"
	case "scanned":
		query += " AND " + assetEffectiveLastScanExpr + " IS NOT NULL"
	}
	if filter.ScanOverdueDays != nil {
		query += " AND (" + assetEffectiveLastScanExpr + " IS NULL OR " + assetEffectiveLastScanExpr + " < ?)"
		args = append(args, time.Now().AddDate(0, 0, -*filter.ScanOverdueDays))
	}
	if filter.LastScanBefore != nil {
		query += " AND " + assetEffectiveLastScanExpr + " < ?"
		args = append(args, *filter.LastScanBefore)
	}
	if filter.LastScanAfter != nil {
		query += " AND " + assetEffectiveLastScanExpr + " > ?"
		args = append(args, *filter.LastScanAfter)
	}
	if filter.FirstSeenBefore != nil {
		query += " AND assets.first_seen_at < ?"
		args = append(args, *filter.FirstSeenBefore)
	}
	if filter.FirstSeenAfter != nil {
		query += " AND assets.first_seen_at > ?"
		args = append(args, *filter.FirstSeenAfter)
	}
	if filter.LastSeenBefore != nil {
		query += " AND assets.last_seen_at < ?"
		args = append(args, *filter.LastSeenBefore)
	}
	if filter.LastSeenAfter != nil {
		query += " AND assets.last_seen_at > ?"
		args = append(args, *filter.LastSeenAfter)
	}
	return appendAssetAccess(query, args, access, "assets")
}

func escapeAssetLike(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `%`, `\%`)
	return strings.ReplaceAll(value, `_`, `\_`)
}

func scanAsset(scanner interface{ Scan(...interface{}) error }) (*Asset, error) {
	var a Asset
	var tags string
	var lastScanAt interface{}
	err := scanner.Scan(&a.ID, &a.ProjectID, &a.ProjectName, &a.Host, &a.IP, &a.Port, &a.Domain, &a.Protocol, &a.Title, &a.Server, &a.Country,
		&a.Province, &a.City, &a.ResponsiblePerson, &a.Department, &a.BusinessSystem, &a.Environment, &a.Criticality,
		&a.Source, &a.SourceQuery, &a.Status, &tags, &a.FirstSeenAt, &a.LastSeenAt, &a.CreatedAt, &a.UpdatedAt,
		&lastScanAt, &a.LastScanConversationID, &a.LastScanQueueID, &a.LastScanTaskID, &a.VulnerabilityCount, &a.RiskLevel)
	if err != nil {
		return nil, err
	}
	if parsed, ok := parseAssetScanTime(lastScanAt); ok {
		a.LastScanAt = &parsed
	}
	_ = json.Unmarshal([]byte(tags), &a.Tags)
	return &a, nil
}

func parseAssetScanTime(value interface{}) (time.Time, bool) {
	if value == nil {
		return time.Time{}, false
	}
	if parsed, ok := value.(time.Time); ok {
		return parsed, true
	}
	var raw string
	switch typed := value.(type) {
	case string:
		raw = typed
	case []byte:
		raw = string(typed)
	default:
		raw = fmt.Sprint(typed)
	}
	for _, layout := range []string{
		time.RFC3339Nano,
		"2006-01-02 15:04:05.999999999-07:00",
		"2006-01-02 15:04:05.999999999Z07:00",
		"2006-01-02 15:04:05-07:00",
		"2006-01-02 15:04:05",
	} {
		if parsed, err := time.Parse(layout, strings.TrimSpace(raw)); err == nil {
			return parsed, true
		}
	}
	return time.Time{}, false
}

const assetEffectiveLastScanExpr = `COALESCE(
		(SELECT bt.completed_at FROM batch_tasks bt WHERE bt.id=assets.last_scan_task_id AND bt.completed_at IS NOT NULL LIMIT 1),
		(SELECT MAX(m.updated_at) FROM messages m WHERE m.conversation_id=assets.last_scan_conversation_id AND m.role='assistant'),
		assets.last_scan_at
	)`

const assetVulnerabilityMatchExpr = `(
	(COALESCE(assets.last_scan_conversation_id,'')<>'' AND v.conversation_id=assets.last_scan_conversation_id)
	OR (COALESCE(assets.last_scan_task_id,'')<>'' AND EXISTS (
		SELECT 1 FROM batch_tasks bt WHERE bt.id=assets.last_scan_task_id AND bt.conversation_id=v.conversation_id
	))
)`

const assetVulnerabilityCountExpr = `(SELECT COUNT(DISTINCT v.id) FROM vulnerabilities v WHERE ` + assetVulnerabilityMatchExpr + `)`

const assetRiskScoreExpr = `COALESCE((
	SELECT MAX(CASE LOWER(COALESCE(v.severity,'')) WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3 WHEN 'low' THEN 2 WHEN 'info' THEN 1 ELSE 0 END)
	FROM vulnerabilities v
	WHERE LOWER(COALESCE(v.status,'open')) NOT IN ('fixed','false_positive','ignored') AND ` + assetVulnerabilityMatchExpr + `
),0)`

const assetRiskLevelExpr = `(CASE WHEN ` + assetEffectiveLastScanExpr + ` IS NULL THEN 'unassessed' ELSE CASE ` + assetRiskScoreExpr + `
	WHEN 5 THEN 'critical' WHEN 4 THEN 'high' WHEN 3 THEN 'medium' WHEN 2 THEN 'low' WHEN 1 THEN 'info' ELSE 'normal' END END)`

const assetSelectColumns = `assets.id,COALESCE(assets.project_id,''),COALESCE(p.name,''),assets.host,assets.ip,assets.port,assets.domain,assets.protocol,assets.title,assets.server,assets.country,
	assets.province,assets.city,assets.responsible_person,assets.department,assets.business_system,assets.environment,assets.criticality,
	assets.source,assets.source_query,assets.status,assets.tags_json,assets.first_seen_at,assets.last_seen_at,assets.created_at,assets.updated_at,
	` + assetEffectiveLastScanExpr + `,COALESCE(assets.last_scan_conversation_id,''),COALESCE(assets.last_scan_queue_id,''),COALESCE(assets.last_scan_task_id,''),
	` + assetVulnerabilityCountExpr + `,` + assetRiskLevelExpr

// MarkAssetScanned links an asset to the conversation or batch subtask created from it.
// The link lets the asset list show the latest scan time and vulnerabilities produced by that scan.
func (db *DB) MarkAssetScanned(id, conversationID, queueID, taskID string, access RBACListAccess) error {
	where, args := appendAssetAccess(" WHERE id = ?", []interface{}{strings.TrimSpace(id)}, access, "assets")
	res, err := db.Exec(`UPDATE assets SET last_scan_at=?,last_scan_conversation_id=?,last_scan_queue_id=?,last_scan_task_id=?,updated_at=?`+where,
		append([]interface{}{time.Now(), strings.TrimSpace(conversationID), strings.TrimSpace(queueID), strings.TrimSpace(taskID), time.Now()}, args...)...)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// CompleteAssetScan records completion from inside an Agent conversation. If
// the asset was launched as a batch task, keep its task/queue link only when
// that task belongs to the current conversation; a later ad-hoc chat scan must
// not retain stale task associations.
// CompleteAssetScanForProject additionally enforces membership in the bound
// conversation's project in the mutation statement itself.
func (db *DB) CompleteAssetScanForProject(id, conversationID string, access RBACListAccess, projectID string) error {
	return db.completeAssetScan(id, conversationID, access, projectID)
}

func (db *DB) CompleteAssetScan(id, conversationID string, access RBACListAccess) error {
	return db.completeAssetScan(id, conversationID, access, "")
}

func (db *DB) completeAssetScan(id, conversationID string, access RBACListAccess, projectID string) error {
	id = strings.TrimSpace(id)
	conversationID = strings.TrimSpace(conversationID)
	if conversationID == "" {
		return fmt.Errorf("扫描对话不能为空")
	}
	where, args := appendAssetProjectScope(" WHERE assets.id = ?", []interface{}{id}, projectID)
	where, args = appendAssetAccess(where, args, access, "assets")
	now := time.Now()
	res, err := db.Exec(`UPDATE assets SET
		last_scan_at=?,last_scan_conversation_id=?,
		last_scan_queue_id=CASE WHEN EXISTS (SELECT 1 FROM batch_tasks bt WHERE bt.id=assets.last_scan_task_id AND bt.conversation_id=?) THEN last_scan_queue_id ELSE '' END,
		last_scan_task_id=CASE WHEN EXISTS (SELECT 1 FROM batch_tasks bt WHERE bt.id=assets.last_scan_task_id AND bt.conversation_id=?) THEN last_scan_task_id ELSE '' END,
		updated_at=?`+where,
		append([]interface{}{now, conversationID, conversationID, conversationID, now}, args...)...)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (db *DB) BatchTaskBelongsToQueue(taskID, queueID string) bool {
	var count int
	err := db.QueryRow(`SELECT COUNT(*) FROM batch_tasks WHERE id=? AND queue_id=?`, strings.TrimSpace(taskID), strings.TrimSpace(queueID)).Scan(&count)
	return err == nil && count > 0
}

func (db *DB) ListAssets(limit, offset int, filter AssetListFilter, access RBACListAccess) ([]*Asset, int, error) {
	if limit < 1 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	where, args := assetWhere(filter, access)
	var total int
	if err := db.QueryRow("SELECT COUNT(*) FROM assets"+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	orderBy := assetOrderBy(filter.SortBy, filter.SortOrder)
	rows, err := db.Query("SELECT "+assetSelectColumns+" FROM assets LEFT JOIN projects p ON p.id=assets.project_id"+where+" ORDER BY "+orderBy+" LIMIT ? OFFSET ?", append(args, limit, offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	items := []*Asset{}
	for rows.Next() {
		a, err := scanAsset(rows)
		if err != nil {
			return nil, 0, err
		}
		items = append(items, a)
	}
	return items, total, rows.Err()
}

// ListAssetsForOperation resolves the complete filtered selection used by
// cross-page bulk actions. The caller supplies a strict upper bound.
func (db *DB) ListAssetsForOperation(limit int, filter AssetListFilter, access RBACListAccess) ([]*Asset, int, error) {
	if limit < 1 || limit > 10000 {
		limit = 10000
	}
	where, args := assetWhere(filter, access)
	var total int
	if err := db.QueryRow("SELECT COUNT(*) FROM assets"+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	if total > limit {
		return nil, total, fmt.Errorf("匹配资产超过 %d 条，请缩小筛选范围", limit)
	}
	rows, err := db.Query("SELECT "+assetSelectColumns+" FROM assets LEFT JOIN projects p ON p.id=assets.project_id"+where+" ORDER BY "+assetOrderBy(filter.SortBy, filter.SortOrder), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	items := make([]*Asset, 0, total)
	for rows.Next() {
		item, err := scanAsset(rows)
		if err != nil {
			return nil, 0, err
		}
		items = append(items, item)
	}
	return items, total, rows.Err()
}

func assetOrderBy(sortBy, sortOrder string) string {
	direction := "DESC"
	if strings.EqualFold(strings.TrimSpace(sortOrder), "asc") {
		direction = "ASC"
	}
	var expression string
	switch strings.ToLower(strings.TrimSpace(sortBy)) {
	case "last_scan_at":
		expression = assetEffectiveLastScanExpr
		// For oldest-first queries, assets that have never been scanned are the
		// most overdue and intentionally appear first. NULLs stay last for DESC.
		if direction == "ASC" {
			return "CASE WHEN " + expression + " IS NULL THEN 0 ELSE 1 END ASC, " + expression + " ASC, assets.id ASC"
		}
		return "CASE WHEN " + expression + " IS NULL THEN 1 ELSE 0 END ASC, " + expression + " DESC, assets.id ASC"
	case "first_seen_at":
		expression = "assets.first_seen_at"
	case "created_at":
		expression = "assets.created_at"
	case "updated_at":
		expression = "assets.updated_at"
	case "host":
		expression = "LOWER(assets.host)"
	case "port":
		expression = "assets.port"
	case "vulnerability_count":
		expression = assetVulnerabilityCountExpr
	case "risk_level":
		expression = assetRiskScoreExpr
	default:
		expression = "assets.last_seen_at"
	}
	return expression + " " + direction + ", assets.id ASC"
}

func (db *DB) GetAsset(id string, access RBACListAccess) (*Asset, error) {
	query, args := appendAssetAccess("SELECT "+assetSelectColumns+" FROM assets LEFT JOIN projects p ON p.id=assets.project_id WHERE assets.id = ?", []interface{}{id}, access, "assets")
	return scanAsset(db.QueryRow(query, args...))
}

func (db *DB) UpdateAsset(id string, a *Asset, access RBACListAccess) error {
	return db.updateAsset(id, a, access, "")
}

// UpdateAssetForProject keeps the project's membership check inside the same
// transaction as the mutation. A shared asset keeps its legacy primary project
// while observations are attributed to the current project's association.
func (db *DB) UpdateAssetForProject(id string, a *Asset, access RBACListAccess, projectID string) error {
	projectID = strings.TrimSpace(projectID)
	if a == nil || (projectID != "" && strings.TrimSpace(a.ProjectID) != projectID) {
		return fmt.Errorf("资产更新项目与当前对话项目不一致")
	}
	return db.updateAsset(id, a, access, projectID)
}

func (db *DB) updateAsset(id string, a *Asset, access RBACListAccess, projectScope string) error {
	id = strings.TrimSpace(id)
	if a == nil {
		return assetValidationErrorf("资产不能为空")
	}
	copy := *a
	copy.Tags = append([]string(nil), a.Tags...)
	normalizeAsset(&copy)
	if err := validateAsset(&copy); err != nil {
		return err
	}
	key := assetDedupKey(&copy)
	tags, _ := json.Marshal(copy.Tags)
	var committedProject string
	var committedAt time.Time
	err := db.withAssetTransaction(func(tx *Tx) error {
		where, args := appendAssetProjectScope(" WHERE assets.id=?", []interface{}{strings.TrimSpace(id)}, projectScope)
		where, args = appendAssetAccess(where, args, access, "assets")
		var primaryProject, previousIP, previousSource, previousQuery string
		if err := tx.QueryRow(`SELECT COALESCE(project_id,''),ip,source,source_query FROM assets`+where+db.assetRowLock(), args...).Scan(&primaryProject, &previousIP, &previousSource, &previousQuery); err != nil {
			return err
		}
		now := time.Now().UTC()
		legacyProject := primaryProject
		if copy.ProjectID == "" {
			// Retain explicit legacy unbinding outside a bound conversation.
			legacyProject = ""
			if _, err := tx.Exec(`DELETE FROM asset_project_links WHERE asset_id=?`, id); err != nil {
				return err
			}
		} else {
			if copy.ProjectID != primaryProject {
				if err := checkAssetProjectAccess(tx, copy.ProjectID, access); err != nil {
					return err
				}
			}
			if err := linkAssetProject(tx, id, copy.ProjectID, now); err != nil {
				return err
			}
			if legacyProject == "" {
				legacyProject = copy.ProjectID
			}
		}
		res, err := tx.Exec(`UPDATE assets SET dedup_key=?,project_id=?,host=?,ip=?,port=?,domain=?,protocol=?,title=?,server=?,country=?,province=?,city=?,
			responsible_person=?,department=?,business_system=?,environment=?,criticality=?,source=?,source_query=?,status=?,tags_json=?,updated_at=?`+where,
			append([]interface{}{key, nullIfEmpty(legacyProject), copy.Host, copy.IP, copy.Port, copy.Domain, copy.Protocol, copy.Title, copy.Server, copy.Country, copy.Province, copy.City,
				copy.ResponsiblePerson, copy.Department, copy.BusinessSystem, copy.Environment, copy.Criticality, copy.Source, copy.SourceQuery, copy.Status, string(tags), now}, args...)...)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n == 0 {
			return sql.ErrNoRows
		}
		committedProject, committedAt = legacyProject, now
		// A metadata-only patch is not a new IP observation. In particular,
		// do not fabricate project B evidence from project A's primary IP.
		if copy.Observation == nil && copy.IP == previousIP && copy.Source == previousSource && copy.SourceQuery == previousQuery {
			return nil
		}
		return appendAssetObservation(tx, id, &copy, now)
	})
	if err != nil {
		return err
	}
	copy.ID, copy.ProjectID, copy.UpdatedAt = id, committedProject, committedAt
	*a = copy
	return nil
}

type AssetBulkPatch struct {
	Status            *string
	ResponsiblePerson *string
	Department        *string
	BusinessSystem    *string
	Environment       *string
	Criticality       *string
	AddTags           []string
	RemoveTags        []string
}

func normalizeAssetIDs(ids []string) []string {
	unique := make([]string, 0, len(ids))
	seen := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if _, exists := seen[id]; exists {
			continue
		}
		seen[id] = struct{}{}
		unique = append(unique, id)
	}
	return unique
}

func normalizeBulkTags(tags []string) ([]string, error) {
	seen := map[string]struct{}{}
	result := make([]string, 0, len(tags))
	for _, tag := range tags {
		tag = strings.TrimSpace(tag)
		if tag == "" {
			continue
		}
		if utf8.RuneCountInString(tag) > 64 {
			return nil, assetValidationErrorf("单个标签不能超过 64 个字符")
		}
		if _, exists := seen[tag]; exists {
			continue
		}
		seen[tag] = struct{}{}
		result = append(result, tag)
	}
	return result, nil
}

// UpdateAssetsBulk atomically applies operational metadata to a selected set.
func (db *DB) UpdateAssetsBulk(ids []string, patch AssetBulkPatch, access RBACListAccess) (int, error) {
	unique := normalizeAssetIDs(ids)
	if len(unique) == 0 {
		return 0, fmt.Errorf("资产列表不能为空")
	}
	if patch.Status != nil {
		value := strings.ToLower(strings.TrimSpace(*patch.Status))
		if value != "active" && value != "inactive" {
			return 0, assetValidationErrorf("资产状态必须为 active 或 inactive")
		}
		patch.Status = &value
	}
	if patch.Environment != nil {
		value := strings.ToLower(strings.TrimSpace(*patch.Environment))
		if !oneOfAssetValue(value, "", "production", "staging", "testing", "development", "other") {
			return 0, assetValidationErrorf("环境值无效")
		}
		patch.Environment = &value
	}
	if patch.Criticality != nil {
		value := strings.ToLower(strings.TrimSpace(*patch.Criticality))
		if !oneOfAssetValue(value, "", "critical", "high", "medium", "low") {
			return 0, assetValidationErrorf("重要性值无效")
		}
		patch.Criticality = &value
	}
	var err error
	if patch.AddTags, err = normalizeBulkTags(patch.AddTags); err != nil {
		return 0, err
	}
	if patch.RemoveTags, err = normalizeBulkTags(patch.RemoveTags); err != nil {
		return 0, err
	}

	tx, err := db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(unique)), ",")
	idArgs := make([]interface{}, len(unique))
	for i, id := range unique {
		idArgs[i] = id
	}
	countQuery, countArgs := appendAssetAccess("SELECT COUNT(*) FROM assets WHERE id IN ("+placeholders+")", idArgs, access, "assets")
	var accessible int
	if err := tx.QueryRow(countQuery, countArgs...).Scan(&accessible); err != nil {
		return 0, err
	}
	if accessible != len(unique) {
		return 0, fmt.Errorf("部分资产不存在或无权更新")
	}

	for _, id := range unique {
		var rawTags string
		if err := tx.QueryRow("SELECT tags_json FROM assets WHERE id=?", id).Scan(&rawTags); err != nil {
			return 0, err
		}
		tags := []string{}
		_ = json.Unmarshal([]byte(rawTags), &tags)
		remove := map[string]struct{}{}
		for _, tag := range patch.RemoveTags {
			remove[tag] = struct{}{}
		}
		merged := make([]string, 0, len(tags)+len(patch.AddTags))
		seen := map[string]struct{}{}
		for _, tag := range append(tags, patch.AddTags...) {
			if _, removed := remove[tag]; removed {
				continue
			}
			if _, exists := seen[tag]; exists {
				continue
			}
			seen[tag] = struct{}{}
			merged = append(merged, tag)
		}
		if len(merged) > 30 {
			return 0, assetValidationErrorf("批量修改后标签不能超过 30 个")
		}
		tagsJSON, _ := json.Marshal(merged)
		_, err := tx.Exec(`UPDATE assets SET
			status=CASE WHEN ? THEN ? ELSE status END,
			responsible_person=CASE WHEN ? THEN ? ELSE responsible_person END,
			department=CASE WHEN ? THEN ? ELSE department END,
			business_system=CASE WHEN ? THEN ? ELSE business_system END,
			environment=CASE WHEN ? THEN ? ELSE environment END,
			criticality=CASE WHEN ? THEN ? ELSE criticality END,
			tags_json=?,updated_at=? WHERE id=?`,
			patch.Status != nil, valueOrEmpty(patch.Status),
			patch.ResponsiblePerson != nil, valueOrEmpty(patch.ResponsiblePerson),
			patch.Department != nil, valueOrEmpty(patch.Department),
			patch.BusinessSystem != nil, valueOrEmpty(patch.BusinessSystem),
			patch.Environment != nil, valueOrEmpty(patch.Environment),
			patch.Criticality != nil, valueOrEmpty(patch.Criticality),
			string(tagsJSON), time.Now(), id)
		if err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return len(unique), nil
}

func valueOrEmpty(value *string) string {
	if value == nil {
		return ""
	}
	return strings.TrimSpace(*value)
}

func (db *DB) DeleteAssets(ids []string, access RBACListAccess) (int, error) {
	unique := normalizeAssetIDs(ids)
	if len(unique) == 0 {
		return 0, fmt.Errorf("资产列表不能为空")
	}
	tx, err := db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(unique)), ",")
	args := make([]interface{}, len(unique))
	for i, id := range unique {
		args[i] = id
	}
	countQuery, countArgs := appendAssetAccess("SELECT COUNT(*) FROM assets WHERE id IN ("+placeholders+")", args, access, "assets")
	var accessible int
	if err := tx.QueryRow(countQuery, countArgs...).Scan(&accessible); err != nil {
		return 0, err
	}
	if accessible != len(unique) {
		return 0, fmt.Errorf("部分资产不存在或无权删除")
	}
	deleteQuery, deleteArgs := appendAssetAccess("DELETE FROM assets WHERE id IN ("+placeholders+")", args, access, "assets")
	result, err := tx.Exec(deleteQuery, deleteArgs...)
	if err != nil {
		return 0, err
	}
	deleted, err := result.RowsAffected()
	if err != nil || int(deleted) != len(unique) {
		return 0, fmt.Errorf("批量删除资产失败")
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return int(deleted), nil
}

// MergeAssets atomically updates the surviving asset and removes duplicates.
// Separate access scopes preserve permission-specific RBAC boundaries.
func (db *DB) MergeAssets(primary *Asset, duplicateIDs []string, writeAccess, deleteAccess RBACListAccess) (int, error) {
	if primary == nil || strings.TrimSpace(primary.ID) == "" {
		return 0, fmt.Errorf("主资产不能为空")
	}
	normalizeAsset(primary)
	if err := validateAsset(primary); err != nil {
		return 0, err
	}
	duplicates := normalizeAssetIDs(duplicateIDs)
	filtered := duplicates[:0]
	for _, id := range duplicates {
		if id != primary.ID {
			filtered = append(filtered, id)
		}
	}
	duplicates = filtered
	if len(duplicates) == 0 {
		return 0, fmt.Errorf("重复资产列表不能为空")
	}
	key := assetDedupKey(primary)
	tagsJSON, _ := json.Marshal(primary.Tags)

	tx, err := db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	primaryQuery, primaryArgs := appendAssetAccess("SELECT COALESCE(project_id,'') FROM assets WHERE id=?", []interface{}{primary.ID}, writeAccess, "assets")
	var legacyProject string
	if err := tx.QueryRow(primaryQuery+db.assetRowLock(), primaryArgs...).Scan(&legacyProject); err != nil {
		return 0, fmt.Errorf("主资产不存在或无权更新")
	}
	if primary.ProjectID != "" && primary.ProjectID != legacyProject {
		if err := checkAssetProjectAccess(tx, primary.ProjectID, writeAccess); err != nil {
			return 0, err
		}
	}
	if legacyProject == "" {
		legacyProject = primary.ProjectID
	}
	if err := linkAssetProject(tx, primary.ID, primary.ProjectID, time.Now().UTC()); err != nil {
		return 0, err
	}
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(duplicates)), ",")
	deleteArgs := make([]interface{}, len(duplicates))
	for i, id := range duplicates {
		deleteArgs[i] = id
	}
	countQuery, countArgs := appendAssetAccess("SELECT COUNT(*) FROM assets WHERE id IN ("+placeholders+")", deleteArgs, deleteAccess, "assets")
	var accessible int
	if err := tx.QueryRow(countQuery, countArgs...).Scan(&accessible); err != nil || accessible != len(duplicates) {
		return 0, fmt.Errorf("部分重复资产不存在或无权删除")
	}
	for _, duplicateID := range duplicates {
		if err := mergeAssetRelations(tx, primary.ID, duplicateID); err != nil {
			return 0, err
		}
	}
	deleteQuery, scopedDeleteArgs := appendAssetAccess("DELETE FROM assets WHERE id IN ("+placeholders+")", deleteArgs, deleteAccess, "assets")
	if result, err := tx.Exec(deleteQuery, scopedDeleteArgs...); err != nil {
		return 0, err
	} else if deleted, _ := result.RowsAffected(); int(deleted) != len(duplicates) {
		return 0, fmt.Errorf("删除重复资产失败")
	}
	updateQuery, updateScopeArgs := appendAssetAccess(`UPDATE assets SET dedup_key=?,project_id=?,host=?,ip=?,port=?,domain=?,protocol=?,title=?,server=?,country=?,province=?,city=?,
		responsible_person=?,department=?,business_system=?,environment=?,criticality=?,source=?,source_query=?,status=?,tags_json=?,updated_at=? WHERE id=?`,
		[]interface{}{key, nullIfEmpty(legacyProject), primary.Host, primary.IP, primary.Port, primary.Domain, primary.Protocol, primary.Title, primary.Server,
			primary.Country, primary.Province, primary.City, primary.ResponsiblePerson, primary.Department, primary.BusinessSystem, primary.Environment,
			primary.Criticality, primary.Source, primary.SourceQuery, primary.Status, string(tagsJSON), time.Now(), primary.ID}, writeAccess, "assets")
	result, err := tx.Exec(updateQuery, updateScopeArgs...)
	if err != nil {
		return 0, err
	}
	if updated, _ := result.RowsAffected(); updated != 1 {
		return 0, fmt.Errorf("更新主资产失败")
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return len(duplicates), nil
}

// UpdateAssetsProject atomically adds a project association without replacing
// an existing primary project. An explicitly empty project removes all current
// associations (the legacy unbind operation), but retains observation history.
// Every requested asset and destination project must be accessible.
func (db *DB) UpdateAssetsProject(ids []string, projectID string, access RBACListAccess) (int, error) {
	unique := normalizeAssetIDs(ids)
	if len(unique) == 0 {
		return 0, fmt.Errorf("资产列表不能为空")
	}
	sort.Strings(unique)
	projectID = strings.TrimSpace(projectID)
	err := db.withAssetTransaction(func(tx *Tx) error {
		placeholders := strings.TrimSuffix(strings.Repeat("?,", len(unique)), ",")
		idArgs := make([]interface{}, len(unique))
		for i, id := range unique {
			idArgs[i] = id
		}
		countQuery, countArgs := appendAssetAccess("SELECT COUNT(*) FROM assets WHERE id IN ("+placeholders+")", idArgs, access, "assets")
		var accessible int
		if err := tx.QueryRow(countQuery, countArgs...).Scan(&accessible); err != nil {
			return err
		}
		if accessible != len(unique) {
			return fmt.Errorf("部分资产不存在或无权更新")
		}
		if err := checkAssetProjectAccess(tx, projectID, access); err != nil {
			return err
		}
		now := time.Now().UTC()
		for _, id := range unique {
			if projectID == "" {
				if _, err := tx.Exec("DELETE FROM asset_project_links WHERE asset_id=?", id); err != nil {
					return err
				}
			} else if err := linkAssetProject(tx, id, projectID, now); err != nil {
				return err
			}
		}
		setProject := `project_id=CASE WHEN COALESCE(project_id,'')='' THEN ? ELSE project_id END`
		if projectID == "" {
			setProject = `project_id=?`
		}
		updateArgs := append([]interface{}{nullIfEmpty(projectID), now}, idArgs...)
		updateQuery, updateArgs := appendAssetAccess("UPDATE assets SET "+setProject+",updated_at=? WHERE id IN ("+placeholders+")", updateArgs, access, "assets")
		result, err := tx.Exec(updateQuery, updateArgs...)
		if err != nil {
			return err
		}
		updated, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if int(updated) != len(unique) {
			return fmt.Errorf("批量更新资产失败")
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return len(unique), nil
}

func (db *DB) DeleteAsset(id string, access RBACListAccess) error {
	return db.DeleteAssetForProject(id, access, "")
}

func (db *DB) DeleteAssetForProject(id string, access RBACListAccess, projectID string) error {
	where, args := appendAssetProjectScope(" WHERE assets.id = ?", []interface{}{strings.TrimSpace(id)}, projectID)
	where, args = appendAssetAccess(where, args, access, "assets")
	res, err := db.Exec("DELETE FROM assets"+where, args...)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (db *DB) GetAssetStats(access RBACListAccess, requestedDays ...int) (map[string]interface{}, error) {
	days := 30
	if len(requestedDays) > 0 && (requestedDays[0] == 7 || requestedDays[0] == 30 || requestedDays[0] == 90) {
		days = requestedDays[0]
	}
	where, args := appendAssetAccess(" WHERE 1=1", nil, access, "assets")
	stats := map[string]interface{}{}
	recentSince := time.Now().AddDate(0, 0, -7)
	rowArgs := append([]interface{}{recentSince}, args...)
	row := db.QueryRow(`SELECT COUNT(*),COUNT(DISTINCT NULLIF(ip,'')),COUNT(DISTINCT NULLIF(domain,'')),
		COUNT(DISTINCT CASE WHEN port>0 THEN CAST(port AS TEXT) END),
		COALESCE(SUM(CASE WHEN last_seen_at >= ? THEN 1 ELSE 0 END),0) FROM assets`+where, rowArgs...)
	var total, ips, domains, ports, recent int
	if err := row.Scan(&total, &ips, &domains, &ports, &recent); err != nil {
		return nil, err
	}
	stats["total"], stats["ips"], stats["domains"], stats["ports"], stats["recent"] = total, ips, domains, ports, recent
	rows, err := db.Query(`SELECT CASE WHEN protocol='' THEN 'unknown' ELSE protocol END,COUNT(*) FROM assets`+where+` GROUP BY protocol ORDER BY COUNT(*) DESC LIMIT 8`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	dist := []map[string]interface{}{}
	for rows.Next() {
		var name string
		var count int
		if err := rows.Scan(&name, &count); err != nil {
			return nil, err
		}
		dist = append(dist, map[string]interface{}{"name": name, "count": count})
	}
	stats["protocols"] = dist
	stats["period_days"] = days

	coverage := map[string]interface{}{}
	monthSince := time.Now().AddDate(0, 0, -30)
	coverageArgs := append([]interface{}{recentSince, monthSince, monthSince}, args...)
	coverageRow := db.QueryRow(`SELECT
		COALESCE(SUM(CASE WHEN last_scan_at IS NOT NULL THEN 1 ELSE 0 END),0),
		COALESCE(SUM(CASE WHEN last_scan_at >= ? THEN 1 ELSE 0 END),0),
		COALESCE(SUM(CASE WHEN last_scan_at >= ? THEN 1 ELSE 0 END),0),
		COALESCE(SUM(CASE WHEN last_scan_at IS NULL THEN 1 ELSE 0 END),0),
		COALESCE(SUM(CASE WHEN last_scan_at IS NOT NULL AND last_scan_at < ? THEN 1 ELSE 0 END),0),
		COALESCE(SUM(CASE WHEN status='active' THEN 1 ELSE 0 END),0)
		FROM assets`+where, coverageArgs...)
	var scanned, scanned7, scanned30, neverScanned, stale, active int
	if err := coverageRow.Scan(&scanned, &scanned7, &scanned30, &neverScanned, &stale, &active); err != nil {
		return nil, err
	}
	coverage["scanned"], coverage["scanned_7d"], coverage["scanned_30d"] = scanned, scanned7, scanned30
	coverage["never_scanned"], coverage["stale"], coverage["active"] = neverScanned, stale, active
	if total > 0 {
		coverage["rate"] = int(float64(scanned) / float64(total) * 100)
		coverage["recent_rate"] = int(float64(scanned30) / float64(total) * 100)
	} else {
		coverage["rate"], coverage["recent_rate"] = 0, 0
	}
	stats["coverage"] = coverage

	assetDaily := map[string]map[string]int{}
	trendSince := time.Now().AddDate(0, 0, -(days - 1))
	trendWhere, trendArgs := appendAssetAccess(" WHERE first_seen_at >= ?", []interface{}{trendSince}, access, "assets")
	firstSeenDate := db.Dialect().dateTrunc("first_seen_at")
	trendRows, err := db.Query(`SELECT `+firstSeenDate+`, COUNT(*)
		FROM assets`+trendWhere+` GROUP BY `+firstSeenDate+` ORDER BY `+firstSeenDate, trendArgs...)
	if err != nil {
		return nil, err
	}
	for trendRows.Next() {
		var day string
		var added int
		if err := trendRows.Scan(&day, &added); err != nil {
			trendRows.Close()
			return nil, err
		}
		assetDaily[day] = map[string]int{"added": added, "inactive": 0}
	}
	if err := trendRows.Close(); err != nil {
		return nil, err
	}
	inactiveWhere, inactiveArgs := appendAssetAccess(" WHERE status='inactive' AND updated_at >= ?", []interface{}{trendSince}, access, "assets")
	updatedDate := db.Dialect().dateTrunc("updated_at")
	inactiveRows, err := db.Query(`SELECT `+updatedDate+`, COUNT(*) FROM assets`+inactiveWhere+` GROUP BY `+updatedDate+` ORDER BY `+updatedDate, inactiveArgs...)
	if err != nil {
		return nil, err
	}
	for inactiveRows.Next() {
		var day string
		var inactive int
		if err := inactiveRows.Scan(&day, &inactive); err != nil {
			inactiveRows.Close()
			return nil, err
		}
		if _, ok := assetDaily[day]; !ok {
			assetDaily[day] = map[string]int{"added": 0, "inactive": 0}
		}
		assetDaily[day]["inactive"] = inactive
	}
	if err := inactiveRows.Close(); err != nil {
		return nil, err
	}

	riskDaily := map[string]map[string]int{}
	riskWhere, riskArgs := appendVulnerabilityAccessFilter(" WHERE created_at >= ?", []interface{}{trendSince}, access)
	createdDate := db.Dialect().dateTrunc("created_at")
	riskRows, err := db.Query(`SELECT `+createdDate+`, COUNT(*),
		COALESCE(SUM(CASE WHEN LOWER(severity) IN ('critical','high') THEN 1 ELSE 0 END),0)
		FROM vulnerabilities`+riskWhere+` GROUP BY `+createdDate+` ORDER BY `+createdDate, riskArgs...)
	if err != nil {
		return nil, err
	}
	for riskRows.Next() {
		var day string
		var discovered, highRisk int
		if err := riskRows.Scan(&day, &discovered, &highRisk); err != nil {
			riskRows.Close()
			return nil, err
		}
		riskDaily[day] = map[string]int{"discovered": discovered, "high_risk": highRisk}
	}
	if err := riskRows.Close(); err != nil {
		return nil, err
	}

	assetTrend := make([]map[string]interface{}, 0, days)
	riskTrend := make([]map[string]interface{}, 0, days)
	start := time.Now().UTC().Truncate(24*time.Hour).AddDate(0, 0, -(days - 1))
	for i := 0; i < days; i++ {
		day := start.AddDate(0, 0, i).Format("2006-01-02")
		assetPoint := map[string]interface{}{"date": day, "added": 0, "inactive": 0}
		if values, ok := assetDaily[day]; ok {
			assetPoint["added"], assetPoint["inactive"] = values["added"], values["inactive"]
		}
		assetTrend = append(assetTrend, assetPoint)
		riskPoint := map[string]interface{}{"date": day, "discovered": 0, "high_risk": 0}
		if values, ok := riskDaily[day]; ok {
			riskPoint["discovered"], riskPoint["high_risk"] = values["discovered"], values["high_risk"]
		}
		riskTrend = append(riskTrend, riskPoint)
	}
	stats["asset_trend"], stats["risk_trend"] = assetTrend, riskTrend
	return stats, rows.Err()
}
