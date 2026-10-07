// Package mailtd implements the documented receive-only Mail.td REST API.
// API credentials stay server-side; requests never follow redirects or email URLs.
package mailtd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

const BaseURL = "https://api.mail.td"
const maxResponseBytes = 2 << 20

var ErrNotConfigured = errors.New("Mail.td 未配置：设置 MAILTD_API_KEY_FILE（推荐）或 MAILTD_API_KEY 后重启服务")

type Client struct {
	key         string
	baseURL     string
	http        *http.Client
	requests    *rate.Limiter
	creates     *rate.Limiter
	domainMu    sync.Mutex
	domainCache []Domain
	domainsAt   time.Time
}

func New(key string) *Client {
	return &Client{key: strings.TrimSpace(key), baseURL: BaseURL,
		http:     &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		requests: rate.NewLimiter(5, 1), creates: rate.NewLimiter(1, 1)}
}

// FromEnvironment does not include secret values or file contents in errors.
func FromEnvironment() (*Client, error) {
	key := strings.TrimSpace(os.Getenv("MAILTD_API_KEY"))
	if file := strings.TrimSpace(os.Getenv("MAILTD_API_KEY_FILE")); file != "" {
		f, err := os.Open(file)
		if err != nil {
			return nil, errors.New("无法读取 MAILTD_API_KEY_FILE")
		}
		defer f.Close()
		data, err := io.ReadAll(io.LimitReader(f, 4097))
		if err != nil || len(data) > 4096 {
			return nil, errors.New("MAILTD_API_KEY_FILE 无效或过大")
		}
		key = strings.TrimSpace(string(data))
	}
	if key == "" {
		return nil, nil
	}
	if !strings.HasPrefix(key, "td_") || strings.ContainsAny(key, " \r\n\t") {
		return nil, errors.New("Mail.td API 密钥格式无效")
	}
	return New(key), nil
}

type APIError struct {
	Status     int
	Code       string
	RetryAfter int
}

func (e *APIError) Error() string {
	return fmt.Sprintf("Mail.td HTTP %d (%s), retry_after_seconds=%d；不要重复创建或绕过配额", e.Status, e.Code, e.RetryAfter)
}

type Domain struct {
	ID      string `json:"id"`
	Domain  string `json:"domain"`
	Default bool   `json:"default"`
}
type Account struct {
	ID      string `json:"id"`
	Address string `json:"address"`
}
type Message struct {
	ID        string          `json:"id"`
	Sender    string          `json:"sender"`
	From      json.RawMessage `json:"from,omitempty"`
	Subject   string          `json:"subject"`
	Preview   string          `json:"preview_text,omitempty"`
	CreatedAt string          `json:"created_at"`
	Text      string          `json:"text_body,omitempty"`
	HTML      string          `json:"html_body,omitempty"`
}
type MessagePage struct {
	Messages []Message `json:"messages"`
	Page     int       `json:"page"`
}

func safePart(value string) (string, error) {
	if value == "" || len(value) > 254 || strings.ContainsAny(value, "/\\%?#\r\n\t ") || value == "." || value == ".." {
		return "", errors.New("invalid mailbox or message identifier")
	}
	return url.PathEscape(value), nil
}

func (c *Client) request(ctx context.Context, method, path string, input, output any) error {
	if c == nil || c.key == "" {
		return ErrNotConfigured
	}
	if err := c.requests.Wait(ctx); err != nil {
		return ctxError(ctx)
	}
	var body []byte
	var err error
	if input != nil {
		body, err = json.Marshal(input)
		if err != nil {
			return errors.New("invalid Mail.td request")
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return errors.New("invalid Mail.td endpoint")
	}
	req.Header.Set("Authorization", "Bearer "+c.key)
	req.Header.Set("Accept", "application/json")
	if input != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errors.New("Mail.td 请求失败或超时；请核对已有邮箱，禁止盲目重复创建")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Only documented error codes are safe to surface; never echo messages,
		// addresses, credentials, or arbitrary provider error fields.
		code := http.StatusText(resp.StatusCode)
		var api struct {
			Error string `json:"error"`
		}
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if json.Unmarshal(data, &api) == nil {
			switch api.Error {
			case "invalid_address", "invalid_domain", "password_too_short", "invalid_or_expired_token", "account_revoked", "access_denied", "pro_required", "account_limit_reached", "address_taken", "not_found", "expired", "rate_limit_exceeded", "ops_quota_exceeded":
				code = api.Error
			}
		}
		delay, _ := strconv.Atoi(resp.Header.Get("Retry-After"))
		if delay < 0 {
			delay = 0
		}
		if delay > 300 {
			delay = 300
		}
		return &APIError{Status: resp.StatusCode, Code: code, RetryAfter: delay}
	}
	if output == nil {
		return nil
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return errors.New("读取 Mail.td 响应失败")
	}
	if len(data) > maxResponseBytes {
		return errors.New("Mail.td 响应超过 2 MiB，未将截断数据当作完整邮件")
	}
	if err := json.Unmarshal(data, output); err != nil {
		return errors.New("Mail.td 返回非预期 JSON，未将错误页当作空邮箱")
	}
	return nil
}
func ctxError(ctx context.Context) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return errors.New("Mail.td 请求等待超出剩余预算")
}
func (c *Client) Domains(ctx context.Context) ([]Domain, error) {
	if c == nil {
		return nil, ErrNotConfigured
	}
	c.domainMu.Lock()
	defer c.domainMu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !c.domainsAt.IsZero() && time.Since(c.domainsAt) < 5*time.Minute {
		return append([]Domain(nil), c.domainCache...), nil
	}
	var v struct {
		Domains []Domain `json:"domains"`
	}
	if err := c.request(ctx, http.MethodGet, "/api/domains", nil, &v); err != nil {
		return nil, err
	}
	c.domainCache = append([]Domain(nil), v.Domains...)
	c.domainsAt = time.Now()
	return v.Domains, nil
}
func (c *Client) Create(ctx context.Context, address, password string) (*Account, error) {
	if c == nil {
		return nil, ErrNotConfigured
	}
	if err := c.creates.Wait(ctx); err != nil {
		return nil, ctxError(ctx)
	}
	var v Account
	err := c.request(ctx, http.MethodPost, "/api/accounts", map[string]string{"address": address, "password": password}, &v)
	if err != nil {
		return nil, err
	}
	if _, err := safePart(v.ID); err != nil || !strings.EqualFold(v.Address, address) {
		return nil, errors.New("Mail.td 创建结果与请求邮箱不符，保留待核实记录")
	}
	return &v, nil
}
func (c *Client) Account(ctx context.Context, id string) (*Account, error) {
	part, err := safePart(id)
	if err != nil {
		return nil, err
	}
	var v Account
	err = c.request(ctx, http.MethodGet, "/api/accounts/"+part, nil, &v)
	if err != nil {
		return nil, err
	}
	if _, err := safePart(v.ID); err != nil {
		return nil, errors.New("Mail.td 返回无效邮箱标识")
	}
	return &v, nil
}
func (c *Client) Messages(ctx context.Context, id string, page int) (*MessagePage, error) {
	part, err := safePart(id)
	if err != nil {
		return nil, err
	}
	if page < 1 || page > 100 {
		return nil, errors.New("page 必须为 1..100")
	}
	var v MessagePage
	err = c.request(ctx, http.MethodGet, "/api/accounts/"+part+"/messages?page="+strconv.Itoa(page), nil, &v)
	return &v, err
}
func (c *Client) Read(ctx context.Context, accountID, messageID string) (*Message, error) {
	a, err := safePart(accountID)
	if err != nil {
		return nil, err
	}
	m, err := safePart(messageID)
	if err != nil {
		return nil, err
	}
	var v Message
	err = c.request(ctx, http.MethodGet, "/api/accounts/"+a+"/messages/"+m, nil, &v)
	if err == nil && v.ID != messageID {
		return nil, errors.New("Mail.td 邮件标识不一致")
	}
	return &v, err
}
func (c *Client) Delete(ctx context.Context, id string) error {
	part, err := safePart(id)
	if err != nil {
		return err
	}
	return c.request(ctx, http.MethodDelete, "/api/accounts/"+part, nil, nil)
}
