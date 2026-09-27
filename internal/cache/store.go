package cache

import (
	"context"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// Store 是页面热数据的短缓存。Redis 不可用时用内存，不阻塞请求。
type Store interface {
	Get(ctx context.Context, key string) ([]byte, bool)
	Set(ctx context.Context, key string, value []byte, ttl time.Duration)
	Delete(ctx context.Context, key string)
}

type memoryStore struct {
	mu    sync.Mutex
	items map[string]memoryItem
}

type memoryItem struct {
	value   []byte
	expires time.Time
}

func NewMemory() Store {
	return &memoryStore{items: map[string]memoryItem{}}
}

func (s *memoryStore) Get(_ context.Context, key string) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok := s.items[key]
	if !ok || time.Now().After(item.expires) {
		delete(s.items, key)
		return nil, false
	}
	return append([]byte(nil), item.value...), true
}

func (s *memoryStore) Set(_ context.Context, key string, value []byte, ttl time.Duration) {
	if ttl <= 0 {
		ttl = time.Minute
	}
	s.mu.Lock()
	s.items[key] = memoryItem{value: append([]byte(nil), value...), expires: time.Now().Add(ttl)}
	s.mu.Unlock()
}

func (s *memoryStore) Delete(_ context.Context, key string) {
	s.mu.Lock()
	delete(s.items, key)
	s.mu.Unlock()
}

type redisStore struct {
	client *redis.Client
	prefix string
}

func OpenRedis(addr, password, prefix string, db int) (Store, error) {
	client := redis.NewClient(&redis.Options{
		Addr:         addr,
		Password:     password,
		DB:           db,
		DialTimeout:  2 * time.Second,
		ReadTimeout:  500 * time.Millisecond,
		WriteTimeout: 500 * time.Millisecond,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, err
	}
	if prefix == "" {
		prefix = "cyberstrike"
	}
	return &redisStore{client: client, prefix: prefix}, nil
}

func (s *redisStore) key(key string) string {
	return s.prefix + ":" + key
}

func (s *redisStore) Get(ctx context.Context, key string) ([]byte, bool) {
	value, err := s.client.Get(ctx, s.key(key)).Bytes()
	if err != nil {
		return nil, false
	}
	return value, true
}

func (s *redisStore) Set(ctx context.Context, key string, value []byte, ttl time.Duration) {
	if ttl <= 0 {
		ttl = time.Minute
	}
	_ = s.client.Set(ctx, s.key(key), value, ttl).Err()
}

func (s *redisStore) Delete(ctx context.Context, key string) {
	_ = s.client.Del(ctx, s.key(key)).Err()
}
