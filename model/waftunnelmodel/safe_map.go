package waftunnelmodel

import (
	"SamWaf/model"
	"sync"
)

// SafeTunnelMap 线程安全的TunnelTarget Map
type SafeTunnelMap struct {
	mu    sync.RWMutex
	items map[string]*TunnelSafe
}

// NewSafeTunnelMap 创建新的安全Map
func NewSafeTunnelMap() *SafeTunnelMap {
	return &SafeTunnelMap{
		items: make(map[string]*TunnelSafe),
	}
}

// Get 获取值
func (m *SafeTunnelMap) Get(key string) (*TunnelSafe, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	val, ok := m.items[key]
	return val, ok
}

// Set 设置值
func (m *SafeTunnelMap) Set(key string, value *TunnelSafe) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.items[key] = value
}

// Delete 删除值
func (m *SafeTunnelMap) Delete(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.items, key)
}

// Range 遍历Map
func (m *SafeTunnelMap) Range(f func(key string, value *TunnelSafe) bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for k, v := range m.items {
		if !f(k, v) {
			break
		}
	}
}

// Len 获取Map长度
func (m *SafeTunnelMap) Len() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.items)
}

// GetAll 获取所有值
func (m *SafeTunnelMap) GetAll() map[string]*TunnelSafe {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make(map[string]*TunnelSafe, len(m.items))
	for k, v := range m.items {
		result[k] = v
	}
	return result
}
func (m *SafeTunnelMap) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.items = make(map[string]*TunnelSafe)
}

// SafeNetMap 线程安全的NetListerOnline Map
type SafeNetMap struct {
	mu    sync.RWMutex
	items map[string]NetRunTime
}

// NewSafeNetMap 创建新的安全Map
func NewSafeNetMap() *SafeNetMap {
	return &SafeNetMap{
		items: make(map[string]NetRunTime),
	}
}

// Get 获取值
func (m *SafeNetMap) Get(key string) (NetRunTime, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	val, ok := m.items[key]
	return val, ok
}

// Set 设置值
func (m *SafeNetMap) Set(key string, value NetRunTime) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.items[key] = value
}

// Delete 删除值
func (m *SafeNetMap) Delete(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.items, key)
}

// Range 遍历Map
func (m *SafeNetMap) Range(f func(key string, value NetRunTime) bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for k, v := range m.items {
		if !f(k, v) {
			break
		}
	}
}

// Len 获取Map长度
func (m *SafeNetMap) Len() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.items)
}

// GetAll 获取所有值
func (m *SafeNetMap) GetAll() map[string]NetRunTime {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make(map[string]NetRunTime, len(m.items))
	for k, v := range m.items {
		result[k] = v
	}
	return result
}
func (m *SafeNetMap) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.items = make(map[string]NetRunTime)
}

// SafeIPBlockListMap 线程安全的IP黑名单Map（存储网站黑名单数据供隧道引擎使用）
type SafeIPBlockListMap struct {
	mu    sync.RWMutex
	items map[string][]model.IPBlockList // key: host_code, value: 该网站的IP黑名单列表
}

// NewSafeIPBlockListMap 创建新的安全IP黑名单Map
func NewSafeIPBlockListMap() *SafeIPBlockListMap {
	return &SafeIPBlockListMap{
		items: make(map[string][]model.IPBlockList),
	}
}

// Update 更新指定网站code的IP黑名单数据
func (m *SafeIPBlockListMap) Update(hostCode string, blockLists []model.IPBlockList) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(blockLists) == 0 {
		delete(m.items, hostCode)
	} else {
		m.items[hostCode] = blockLists
	}
}

// GetAllBlockLists 获取所有网站的黑名单列表（扁平合并）
func (m *SafeIPBlockListMap) GetAllBlockLists() []model.IPBlockList {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]model.IPBlockList, 0)
	for _, lists := range m.items {
		result = append(result, lists...)
	}
	return result
}

// Clear 清空所有数据
func (m *SafeIPBlockListMap) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.items = make(map[string][]model.IPBlockList)
}
