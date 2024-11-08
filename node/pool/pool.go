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

	"golang.org/x/tools/container/intsets"
)

var (
	// 池满员错误
	ErrPoolFulled = errors.New("the pool was fulled")

	// 无匹配错误
	ErrMatched = errors.New("not matched item in pool")
)

// Pool 泛型池。
// 成员约束为指针类型，避免申请过大的初始空间。
// 删除操作仅对目标位置置空，同时用 free 记录被移除成员的位置，
// 因此非常高效。
type Pool[T any] struct {
	queue  []*T       // 存储区
	max    int        // 存储量上限
	cursor int        // 清理点位置游标
	mu     sync.Mutex // 同步器
}

// NewPool 创建一个特定池。
// @size 池的最大容量
func NewPool[T any](size int) *Pool[T] {
	return &Pool[T]{
		queue: make([]*T, 0, size),
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

	sz := len(p.queue)
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

	for i, its := range p.queue {
		if test(its) {
			return remove(p, i)
		}
	}
	return nil
}

// Get 引用一个成员。
// 获取一个随机成员的引用（不会从池中移除）。
// 如果池为空，返回nil。
// @p 目标池
// @return1 成员的位置
// @return2 一个随机成员
func Get[T any](p *Pool[T]) *T {
	p.mu.Lock()
	defer p.mu.Unlock()

	sz := len(p.queue)
	if sz == 0 {
		return nil
	}
	return p.queue[rand.Intn(sz)]
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

	sz := len(p.queue)
	if sz == 0 || count == 0 {
		return nil
	}
	ii := Indexes(sz, count)
	list := make([]*T, len(ii))

	for i, x := range ii {
		list[i] = p.queue[x]
	}
	return list
}

// Take 提取一个成员。
// 随机提取。提取表示会从池内移除该成员。
// @p 目标池
func Take[T any](p *Pool[T]) *T {
	p.mu.Lock()
	defer p.mu.Unlock()

	sz := len(p.queue)
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

	if len(p.queue) == 0 || count == 0 {
		return nil
	}
	if count < 0 || count > len(p.queue) {
		return random(clear(p))
	}
	list := make([]*T, count)

	for i := 0; i < count; i++ {
		// 长度在变
		list[i] = remove(p, rand.Intn(len(p.queue)))
	}
	return list
}

// Unique 集合去重。
// 根据成员字符串化函数判定成员的相等性。
// 因为移除的是重复的成员，所以无需返回该成员。
// 注意：
// 在锁死后操作，因此应当仅用于小型集合。
// @p 目标池
// @str 序列化函数。
// @return 被移除的重复的数量
func Unique[T any](p *Pool[T], str func(*T) string) int {
	p.mu.Lock()
	defer p.mu.Unlock()

	all := len(p.queue)
	max := all
	buf := make(map[string]bool)

	for i := 0; i < max; i++ {
		k := str(p.queue[i])
		if buf[k] {
			remove(p, i)
			i--
			max--
			continue
		}
		buf[k] = true
	}
	return all - len(buf)
}

// Size 返回池的大小。
func Size[T any](p *Pool[T]) int {
	p.mu.Lock()
	defer p.mu.Unlock()

	return len(p.queue)
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

	return len(p.queue) >= p.max
}

// Drop 提取全部成员。
// 池缓存会被清空，清理下标重置。但其它设定保留。
func Drop[T any](p *Pool[T]) []*T {
	p.mu.Lock()
	defer p.mu.Unlock()

	return clear(p)
}

// Cleans 多清理。
// 按游标步进检查清理多个成员，
// 清理时锁定池，测试函数应当即时高效，不占用过多时间。
// 通常只是测试池成员的时间有效性。
// 注意：
// 如果检查到末尾还没有达到计量，则折返头部检查。
// @p 目标池
// @count 清理测试数量
// @test 清除判断函数，返回true时清除
// @return 清理移除的成员集
func Cleans[T any](p *Pool[T], count int, test func(*T) bool) []*T {
	p.mu.Lock()
	defer p.mu.Unlock()

	var dels []*T
	sz := len(p.queue)
	i := p.cursor % sz

	for n := 0; n < count; n++ {
		// 移除时，
		// 末尾成员移入覆盖，因此游标不动。
		if test(p.queue[i]) {
			dels = append(dels, remove(p, i))
		} else {
			i = (i + 1) % sz
		}
	}
	p.cursor = i

	return dels
}

// Clean 清理目标池。
// 逐个迭代池内成员，根据清理函数判断并移除池成员。
// 注意：仅在上一个成员完成测试之后，才开始下一个测试。
// 返回的成员用于可能的资源回收。
//
// 说明：
//   - 测试判断可能需要较长时间，因此会将目标移出池后再测试，如果无需清理则回插入池。
//     这样就不会导致长时间池锁定。
//   - 也因此，如果测试期间其它进程向池添加成员导致池满，则测试成员将无法回插。
//     此时会返回测试成员本身和 ErrPoolFulled 错误。
//   - 因为非锁时期其它操作可能对池造成影响（比如删除），所以本清理策略不保证100%完整。
//
// @ctx 上下文
// @p 目标池
// @test 清除判断函数，返回true时清除
// @return 移除成员的递送通道
func Clean[T any](ctx context.Context, p *Pool[T], test func(*T) bool) <-chan *T {
	ch := make(chan *T, 1)

	go func() {
		defer close(ch)
	loop:
		for n := 0; n < Size(p); n++ {
			select {
			case <-ctx.Done():
				break loop
			default:
				its, err := check(p, test)
				if its == nil {
					continue
				}
				if err != nil {
					log.Printf("Clean pool error on %s with [%s].", err, its)
				}
				ch <- its
			}
		}
	}()
	return ch
}

// CleanN 并发批量清理。
// 一次最多创建N个并发测试进程，提高测试效率。
// 注意回插并不按照取出时的顺序，先结束测试的会先回插。
// 对于网络连接类测试，n值不宜太大。
// 使用：适用于较大的池。
// @ctx 上下文
// @p 目标池
// @n 一次提取的数量
// @test 清除判断函数，返回true时清除
// @return 移出成员集的递送通道
func CleanN[T any](ctx context.Context, p *Pool[T], n int, test func(*T) bool) <-chan *T {
	ch := make(chan *T, 1)
	cnt := make(chan struct{}, n)

	go func() {
		defer close(ch)
		defer close(cnt)

		var wg sync.WaitGroup
	loop:
		for n := 0; n < Size(p); n++ {
			select {
			case <-ctx.Done():
				break loop

			case cnt <- struct{}{}:
				wg.Add(1)

				go func() {
					defer wg.Done()
					checkx(p, test, cnt, ch)
				}()
			}
		}
		wg.Wait()
	}()
	return ch
}

//
// 清理专用
//////////////////////////////////////////////////////////////////////////////

// 提取清理位置的成员。
func cleanTake[T any](p *Pool[T]) *T {
	p.mu.Lock()
	defer p.mu.Unlock()

	return remove(p, p.cursor)
}

// 回插成员到清理位置。
// 算法：与末尾成员置换，成功后移动清理游标。
// 如果池满或位置超出池大小则无法插入，返回错误 ErrPoolFulled。
// @p 目标池
// @item 待插入的成员
func backInsert[T any](p *Pool[T], item *T) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	sz := len(p.queue)
	if sz >= p.max {
		return ErrPoolFulled
	}
	p.queue = insert(p.queue, p.cursor, item)
	// 步进游标
	p.cursor = (p.cursor + 1) % sz

	return nil
}

// 检查游标位置成员。
// 将目标位置的成员提取出来测试，独立于池外以避免长时锁定。
// 如果测试通过，返回目标成员。
// 否则回插，回插成功返回两个nil，否则返回成员和错误。
// 注记：
// 提取和回插调用有锁定操作的函数，以支持并发。
// @p 目标池
// @i 目标位置
// @test 测试函数，返回true为匹配
// @return 目标成员或nil
func check[T any](p *Pool[T], test func(*T) bool) (*T, error) {
	its := cleanTake(p)

	// 有锁定间隙，可能为nil
	if its != nil {
		// 可能耗时……
		if test(its) {
			return its, nil
		}
		// 回插
		if err := backInsert(p, its); err != nil {
			return its, err
		}
	}
	return nil, nil
}

// 限量检查目标位置成员封装。
// 通过外部的cnt管道限制并发量，检查结束后读取计量约束管道，释放限额。
// @p 目标池
// @i 目标位置
// @test 测试函数，返回true为匹配
// @cnt 外部计量限制
// @out 对外递送管道
func checkx[T any](p *Pool[T], test func(*T) bool, cnt <-chan struct{}, out chan<- *T) {
	its, err := check(p, test)

	if its != nil {
		out <- its
	}
	if err != nil {
		log.Printf("Clean pool error on %s with [%s].\n", err, its)
	}
	<-cnt // 释放外部计量
}

//
// 私有辅助
//////////////////////////////////////////////////////////////////////////////

// 添加一个成员。
func add[T any](p *Pool[T], item *T) error {
	if len(p.queue) >= p.max {
		return ErrPoolFulled
	}
	p.queue = append(p.queue, item)
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
	del := p.queue[i]
	sz := len(p.queue)

	p.queue[i] = p.queue[sz-1]
	p.queue = p.queue[:sz-1]

	return del
}

// 移除一段成员。
// 快速移除法：用末尾同样大小的片段来填补。
// 用法：
// 外部保证片段长合法（i+size <= len(x)）。
func removes[T any](p *Pool[T], i, size int) []*T {
	end := i + size
	buf := make([]*T, size)
	mid := len(p.queue) - size

	copy(buf, p.queue[i:end])

	switch true {
	// 刚到末尾
	case end == len(p.queue):
		p.queue = p.queue[:i]
	// 末段局部
	case end > mid:
		n := copy(p.queue[i:end], p.queue[end:])
		p.queue = p.queue[:i+n]
	// 中段
	default:
		copy(p.queue[i:end], p.queue[mid:])
		p.queue = p.queue[:mid]
	}
	return buf
}

// 清除全部
func clear[T any](p *Pool[T]) []*T {
	all := p.queue
	p.cursor = 0
	p.queue = make([]*T, 0, p.max)

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

// Indexes 构造序列随机下标集。
// 如果序列大小不足（小于要求的count），则count为序列大小。
// 传递count为负值表示全部。
// @size 序列大小
// @count 需要的下标数量
// @return 序列范围内的随机下标集
func Indexes(size, count int) []int {
	if count < 0 || count > size {
		count = size
	}
	// // 优化：数量多于一半时
	if count*2 > size {
		return rand.Perm(size)[:count]
	}
	return customPerm(count, size)
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
