// Copyright (c) 2024 @cxio/blockchain
// Released under the MIT license
//////////////////////////////////////////////////////////////////////////////
// 实现一个通用的泛型缓存池。
// 上层复用通常采用组合方式，接口内调用相应的函数即可。
//
// 特点：
// 池内成员没有顺序要求，因此删除操作十分高效（移动末尾成员到删除位置即可）。
// 本池的重点是成员分布和提取有随机性。
//
//////////////////////////////////////////////////////////////////////////////
//

package pool

import (
	"context"
	"errors"
	"log"
	"math/rand"
	"sync"

	"golang.org/x/exp/constraints"
	"golang.org/x/tools/container/intsets"
)

var (
	// 池满员错误
	ErrPoolFulled = errors.New("the pool was fulled")

	// 池成员下标错误
	ErrPoolIndex = errors.New("the pool index failed")

	// 无匹配错误
	ErrMatched = errors.New("not matched item in pool")
)

// Item 键值条目
// 主要用于返回池内成员的引用，包含索引键（下标）。
// 含键方便可能需要的移除操作。
type Item[T any] struct {
	Key   int // 成员键
	Value *T  // 成员值
}

// Pool 泛型池。
// 成员约束为指针类型，避免申请过大的初始空间。
// 删除操作仅对目标位置置空，同时用 free 记录被移除成员的位置，
// 因此非常高效。
type Pool[T any] struct {
	nodes  []*T       // 存储区
	max    int        // 存储量上限
	cursor int        // 清理点位置游标
	mu     sync.Mutex // 同步器
}

// NewPool 创建一个特定池。
// @size 池的最大容量
func NewPool[T any](size int) *Pool[T] {
	return &Pool[T]{
		nodes: make([]*T, 0, size),
		max:   size,
	}
}

// Add 添加成员。
// 如果池已满，添加失败并返回一个ErrPoolFulled错误。
// @p 目标池
// @item 待添加的成员
func Add[T any](p *Pool[T], item *T) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	return add(p, item)
}

// Adds 添加多个成员。
// 按成员实参顺序将之添加到池中，直到完成或池满。
// 返回已经成功添加的成员的数量。
// 使用：
// 通常在已知池未满或刚刚清理之后使用。
// @p 目标池
// @list 成员序列
// @return 完成的数量
func Adds[T any](p *Pool[T], list ...*T) int {
	p.mu.Lock()
	defer p.mu.Unlock()

	for i, its := range list {
		if err := add(p, its); err != nil {
			return i
		}
	}
	return len(list)
}

// Remove 移除池中目标位置的成员。
// 注意目标位置i不能超出池大小，不然会panic。
// @p 目标池
// @i 目标位置
// @return 被移除的成员
func Remove[T any](p *Pool[T], i int) *T {
	p.mu.Lock()
	defer p.mu.Unlock()

	sz := len(p.nodes)

	if i >= sz || sz == 0 {
		return nil
	}
	return remove(p, i)
}

// Removes 移除一段成员。
// 下标应当为正，传递负数会引发painc。
// 如果目标位置下标超出集合大小，无移除，返回nil。
// @p 目标池
// @i 起始位置
// @size 片段长度
// @return 移除的成员清单
func Removes[T any](p *Pool[T], i, size int) []*T {
	p.mu.Lock()
	defer p.mu.Unlock()

	sz := len(p.nodes)
	if i >= sz {
		return nil
	}
	end := i + size

	if end > sz {
		size = sz - i
	}
	return removes(p, i, size)
}

// Dispose 移除一个成员。
// 遍历池内成员，根据测试判断函数决定是否执行移除操作。
// 如果成功移除，返回被移除的成员。
// 如果遍历整个池都没有符合的成员，返回nil。
// 注意：
// 测试函数不应当是一个耗时的操作，否则会导致池被长时间锁定。
// @p 目标池
// @test 测试函数，返回true时移除
// @return 被移除的成员
func Dispose[T any](p *Pool[T], test func(*T) bool) *T {
	p.mu.Lock()
	defer p.mu.Unlock()

	for i, its := range p.nodes {
		if test(its) {
			return remove(p, i)
		}
	}
	return nil
}

// Get 引用一个成员。
// 获取一个随机成员的引用（不会从池中移除）。
// 如果池为空，返回-1和nil。
// @p 目标池
// @return1 成员的位置
// @return2 一个随机成员
func Get[T any](p *Pool[T]) (int, *T) {
	p.mu.Lock()
	defer p.mu.Unlock()

	sz := len(p.nodes)
	if sz == 0 {
		return -1, nil
	}
	i := rand.Intn(sz)

	return i, p.nodes[i]
}

// Take 提取一个成员。
// 随机提取。提取表示会从池内移除该成员。
// @p 目标池
func Take[T any](p *Pool[T]) *T {
	p.mu.Lock()
	defer p.mu.Unlock()

	sz := len(p.nodes)
	if sz == 0 {
		return nil
	}
	return remove(p, rand.Intn(sz))
}

// Takes 提取池内成员。
// 如果池中成员数不足，则提取仅有的成员。
// count为负时表示提取全部。
// 返回集没有特定的顺序，池内的这些成员会被移除。
// @p 目标池
// @count 获取数量
// @return 成员清单
func Takes[T any](p *Pool[T], count int) []*T {
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.nodes) == 0 || count == 0 {
		return nil
	}
	if count < 0 || count > len(p.nodes) {
		return random(clear(p))
	}
	list := make([]*T, count)

	for i := 0; i < count; i++ {
		// 长度在变
		list[i] = remove(p, rand.Intn(len(p.nodes)))
	}
	return list
}

// List 获取成员序列。
// 如果池中成员数不足，则返回仅有的部分。传递count为负值表示全部成员。
// 返回的是成员的引用，顺序已随机化。
// @p 目标池
// @count 获取数量
// @return 成员清单（引用）
func List[T any](p *Pool[T], count int) []*T {
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.nodes) == 0 || count == 0 {
		return nil
	}
	ii := indexes(p.nodes, count)
	list := make([]*T, len(ii))

	for i, x := range ii {
		list[i] = p.nodes[x]
	}
	return list
}

// Items 返回池内条目（含下标）。
// 如果池中成员数不足，则返回仅有的部分。传递count为负值表示全部成员。
// 返回的是成员的引用，顺序已随机化。
// @p 目标池
// @count 获取数量
// @return 条目清单（Key:Value）
func Items[T any](p *Pool[T], count int) []*Item[T] {
	p.mu.Lock()
	defer p.mu.Unlock()

	sz := len(p.nodes)
	if sz == 0 || count == 0 {
		return nil
	}
	if count < 0 || count > sz {
		count = sz
	}
	buf := make([]*Item[T], count)

	for i := 0; i < count; i++ {
		buf[i] = &Item[T]{Key: i, Value: p.nodes[i]}
	}
	return buf
}

// Drop 提取全部成员。
// 池缓存会被清空，清理下标重置。但其它设定保留。
func Drop[T any](p *Pool[T]) []*T {
	p.mu.Lock()
	defer p.mu.Unlock()

	return clear(p)
}

// Size 返回池的大小。
func Size[T any](p *Pool[T]) int {
	p.mu.Lock()
	defer p.mu.Unlock()

	return len(p.nodes)
}

// MaxSize 返回此大小限制。
func MaxSize[T any](p *Pool[T]) int {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.max
}

// IsFulled 池是否已满。
// 即无法再正常添加成员（注：池中也没有空位）。
func IsFulled[T any](p *Pool[T]) bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	return len(p.nodes) >= p.max
}

// Clean 清理目标池。
// 逐个迭代池内成员，根据清理函数判断并移除池成员。
// 返回的成员用于可能的资源回收。
//
// 说明：
//   - 测试判断可能需要较长时间，因此会将目标移出池后再测试，如果无需清理则回插入池。
//     这样就不会导致长时间池锁定。
//   - 也因此，如果测试期间其它进程向池添加成员导致池满，则测试成员将无法回插。
//     此时会返回测试成员本身和 ErrPoolFulled 错误。
//   - 因为非锁时期其它操作可能对池造成影响，比如添加、移除等，
//     因此本清理策略无法保证100%的完整性。
//
// @ctx 上下文
// @p 目标池
// @test 清除判断函数，返回true时清除
// @return 移除成员的递送通道
func Clean[T any](ctx context.Context, p *Pool[T], test func(*T) bool) <-chan *T {
	ch := make(chan *T, 1)

	go func() {
		defer close(ch)

		for n := 0; n < Size(p); n++ {
			select {
			case <-ctx.Done():
				return
			default:
				its, err := check(p, getCursor(p), test)
				if its == nil {
					continue
				}
				if err != nil {
					log.Println("[Warning] clean pool on", err)
				}
				ch <- its
			}
		}
	}()
	return ch
}

// CleanN 批量清理。
// 一次提出N个成员并行测试，以提高测试的效率。
// 单批清理速度取决于最慢的那个成员的测试。
// 对于网络连接类测试，注意n值不宜太大避免资源占用限制。
// 使用：适用于较大的池。
// @ctx 上下文
// @p 目标池
// @n 一次提取的数量
// @test 清除判断函数，返回true时清除
// @return 移出成员集的递送通道
func CleanN[T any](ctx context.Context, p *Pool[T], n int, test func(*T) bool) <-chan []*T {
	ch := make(chan []*T, 1)
	sz := Size(p)

	max := sz / n
	if sz%n != 0 {
		max++
	}
	go func() {
		defer close(ch)

		for n := 0; n < max; n++ {
			select {
			case <-ctx.Done():
				return
			default:
				list, err := checks(p, getCursor(p), n, test)
				if len(list) == 0 {
					continue
				}
				if err != nil {
					log.Println("[Warning] clean pool on", err)
				}
				ch <- list
			}
		}
	}()
	return ch
}

//
// 清理专用
//////////////////////////////////////////////////////////////////////////////

// 获取清理游标。
func getCursor[T any](p *Pool[T]) int {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.cursor
}

// 锁定插入。
// 采用高效插入方式：与末尾成员置换。
// 如果池满或位置超出池大小，则无法插入，返回错误。
// - 池满无法插入，返回池满错误 ErrPoolFulled。
// - 指定位置超出池大小，返回下标错误 ErrPoolIndex。
// @p 目标池
// @i 目标位置（下标）
// @item 待插入的成员
func lockInsert[T any](p *Pool[T], i int, item *T) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	sz := len(p.nodes)
	if sz >= p.max {
		return ErrPoolFulled
	}
	if i > sz {
		i = sz // 末尾添加
	}
	p.nodes = insert(p.nodes, i, item)
	p.cursor = i + 1

	return nil
}

// 锁定插入成员片段。
// 返回集可能是一个空集nil。
// @p 目标池
// @i 插入起点
// @list 待插入成员清单
// @return 未成功插入的部分成员
func lockInserts[T any](p *Pool[T], i int, list []*T) ([]*T, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	sz := len(p.nodes)
	if sz >= p.max {
		return list, ErrPoolFulled
	}
	if i > sz {
		i = sz
	}
	nodes, rest := inserts(p.nodes, i, p.max, list)

	p.nodes = nodes
	p.cursor = i + len(list) - len(rest)

	return rest, nil
}

// 检查目标位置成员。
// 将目标位置的成员提取出来测试，独立于池外以避免长时锁定。
// 如果测试通过，返回目标成员。
// 否则回插，回插成功返回两个nil，否则返回成员和错误。
// 注记：
// 提取和回插调用有锁定操作的函数，以支持并发。
// @p 目标池
// @i 目标位置
// @test 测试函数，返回true为匹配
// @return 目标成员或nil
func check[T any](p *Pool[T], i int, test func(*T) bool) (*T, error) {
	its := Remove(p, i)

	// 有锁定间隙，可能为nil
	if its != nil {
		// 可能耗时……
		if test(its) {
			return its, nil
		}
		// 回插
		if err := lockInsert(p, i, its); err != nil {
			return its, err
		}
	}
	return nil, nil
}

// 并发检查目标段成员。
// 与check逻辑类似，目标成员全部取出后测试，避免长时锁定。
// 耗时取决于最慢的那个条目。
// @p 目标池
// @i 目标起始位置
// @size 片段长度
// @test 测试函数，返回true为匹配
// @return 测试通过的成员清单
func checks[T any](p *Pool[T], i, size int, test func(*T) bool) ([]*T, error) {
	list := Removes(p, i, size)
	if list == nil {
		return nil, nil
	}
	var wg sync.WaitGroup

	del := make([]*T, 0, len(list))
	bak := make([]*T, 0, len(list))
	chdel := make(chan *T)
	chbak := make(chan *T)

	for _, its := range list {
		wg.Add(1)

		go func(x *T) {
			defer wg.Done()

			if test(x) {
				chdel <- x
			} else {
				chbak <- x
			}
		}(its)
	}
	go func() {
		wg.Wait()
		close(chdel)
		close(chbak)
	}()

	for its := range chdel {
		del = append(del, its)
	}
	for its := range chbak {
		bak = append(bak, its)
	}

	// 可用回插
	rest, err := lockInserts(p, i, bak)
	if err != nil {
		log.Println("[Info] back inserts on", err)
	}
	// 回插未完成段追加
	if len(rest) > 0 {
		del = append(del, rest...)
	}
	return del, nil
}

//
// 私有辅助
//////////////////////////////////////////////////////////////////////////////

// 添加一个成员。
func add[T any](p *Pool[T], item *T) error {
	if len(p.nodes) >= p.max {
		return ErrPoolFulled
	}
	p.nodes = append(p.nodes, item)
	return nil
}

// 移除一个成员。
// 采用快速移除方式，末尾的成员移动到当前位置。
// 使用：
// 外部保证下标的合法性。
// @p 目标池
// @i 目标位置
// @return 移除的成员
func remove[T any](p *Pool[T], i int) *T {
	del := p.nodes[i]
	sz := len(p.nodes)

	p.nodes[i] = p.nodes[sz-1]
	p.nodes = p.nodes[:sz-1]

	return del
}

// 移除一段成员。
// 快速移除法：用末尾同样大小的片段来填补。
// 用法：
// 外部保证片段长合法（i+size <= len(x)）。
func removes[T any](p *Pool[T], i, size int) []*T {
	end := i + size
	buf := make([]*T, size)
	mid := len(p.nodes) - size

	copy(buf, p.nodes[i:end])

	switch true {
	// 刚到末尾
	case end == len(p.nodes):
		p.nodes = p.nodes[:i]
	// 末段局部
	case end > mid:
		n := copy(p.nodes[i:end], p.nodes[end:])
		p.nodes = p.nodes[:i+n]
	// 中段
	default:
		copy(p.nodes[i:end], p.nodes[mid:])
		p.nodes = p.nodes[:mid]
	}
	return buf
}

// 清除全部
func clear[T any](p *Pool[T]) []*T {
	all := p.nodes
	p.cursor = 0
	p.nodes = make([]*T, 0, p.max)

	return all
}

// 插入一个成员。
// 无顺序要求，因此采用将目标位置的原值置换到末尾来实现。
// 使用：
// 外部保证下标位置的合法性。
// @list 目标集
// @i 目标位置
// @item 待插入值
// @return 插入成员后的新集
func insert[T any](list []*T, i int, item *T) []*T {
	if i < len(list) {
		cur := list[i]
		list[i] = item
		item = cur
	}
	return append(list, item)
}

// 插入连续多个成员。
// 在目标起点位置i处插入一个片段，但合计总长不超过max。
// 原位置的的片段移动到末尾。
// 返回因超长而未插入的剩余片段。
// @buf 目标集
// @i 插入起点
// @max 总集最大长度
// @list 待插入片段
// @return1 插入片段后的新集合
// @return2 未能插入的剩余片段
func inserts[T any](buf []*T, i, max int, list []*T) ([]*T, []*T) {
	// 可用空间
	can := max - len(buf)
	if can == 0 {
		return buf, list
	}
	use := len(list)
	var rest []*T

	// 可用空间不足
	if use > can {
		rest = make([]*T, use-can)
		use = can
		copy(rest, list[use:])
		list = list[:use]
	}
	// 覆盖终点
	end := i + use

	// 待覆盖段长度不足
	if end > len(buf) {
		list = append(list, buf[i:]...) // 待覆盖片段移到新集之后
		buf = append(buf[i:], list...)  // 整体追加
	} else {
		buf = append(buf, buf[i:end]...) // 待覆盖片段移到原集之后
		copy(buf[i:end], list)           // 定长覆盖
	}

	return buf, rest
}

// 构造池成员随机下标集。
// 如果池中成员数不足，则返回仅有的部分。
// 传递count为负值表示全部。
func indexes[T any](list []*T, count int) []int {
	sz := len(list)

	if count < 0 || count > sz {
		count = sz
	}
	// // 优化：数量多于一半时
	if count*2 > sz {
		return rand.Perm(sz)[:count]
	}
	return customPerm(count, sz)
}

// 集合成员随机化。
// 注意：会改变传递进来的切片本身。
// @return 随机化了的原切片
func random[T any](list []*T) []*T {

	rand.Shuffle(len(list), func(i, j int) {
		list[i], list[j] = list[j], list[i]
	})
	return list
}

//
// 简单工具
//////////////////////////////////////////////////////////////////////////////

// 取通用最小值。
func min[T constraints.Ordered](a, b T) T {
	if a < b {
		return a
	}
	return b
}

// 生成不重复随机值序列。
// 主要用于生成随机索引，以便在一个大的切片中取值。
// 通常，n应当比max小得多。如果差距不大，建议使用rand.Perm即可。
// @n 生成的数量
// @max 最大整数值上界（不含）
func customPerm(n, max int) []int {
	var list []int
	var iset intsets.Sparse

	if n > max {
		log.Fatalln("[Fatal] count large than max.")
	}
	for i := 0; i < n; {
		x := rand.Intn(max)

		if !iset.Has(x) {
			iset.Insert(x)
			list = append(list, x)
			i++
		}
	}
	return list
}
