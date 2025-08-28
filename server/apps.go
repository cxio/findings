// 定向打洞服务部分。

package server

import (
	"sync"
	"time"
)

// PunchApp 打洞应用端
// 用于登记定向打洞的查询目标节点。
type PunchApp struct {
	app     *Applier  // 应用端服务员
	expired time.Time // 过期时间
}

// Expired 是否以及过期。
func (p PunchApp) Expired() bool {
	return time.Now().After(p.expired)
}

// AppMap 应用端集
// 存储应用端关联节点与应用端自身的映射。
// 这是一个支持并发的简单封装，用于定向打洞检索目标节点。
type AppMap struct {
	cache map[string]*PunchApp
	mu    sync.Mutex
}

// NewAppMap 新建一个空映射集。
func NewAppMap() *AppMap {
	return &AppMap{
		cache: make(map[string]*PunchApp),
	}
}

// Add 添加一个映射。
// @app 目标应用端服务员
// @expire 有效期时长
func (c *AppMap) Add(key string, app *Applier, expire time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.cache[key] = &PunchApp{
		app:     app,
		expired: time.Now().Add(expire),
	}
}

// Remove 移除一个映射。
func (c *AppMap) Remove(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.cache, key)
}

// Get 获取目标连接。
// 获取时会检查是否过期，若过期会自动删除目标。
// 作为一种友好，即便过期，目标依然会返回（可用）。
// 即：仅在未找到目标时返回nil。
func (c *AppMap) Get(key string) *Applier {
	c.mu.Lock()
	defer c.mu.Unlock()

	pa, ok := c.cache[key]
	if !ok {
		return nil
	}
	if pa.Expired() {
		delete(c.cache, key)
	}
	return pa.app
}

// Clean 清理过期目标。
// 遍历集合，可能耗时，但Get方法也会及时清理。
func (c *AppMap) Clean() {
	c.mu.Lock()
	defer c.mu.Unlock()

	for k, its := range c.cache {
		if its.Expired() {
			delete(c.cache, k)
		}
	}
}
