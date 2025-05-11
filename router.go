package web

import "strings"

// flow tells the main loop what it should do next.
type flow int

// Control flow values.
const (
	flowStop flow = iota
	flowBegin
	flowNext
)

// Parameter represents a URL parameter.
type Parameter struct {
	Key   string
	Value string
}

// Router is a high-performance router.
type Router[T any] struct {
	get     Tree[T]
	post    Tree[T]
	delete  Tree[T]
	put     Tree[T]
	patch   Tree[T]
	head    Tree[T]
	connect Tree[T]
	trace   Tree[T]
	options Tree[T]
}

// New creates a new router containing trees for every HTTP method.
func New[T any]() *Router[T] {
	return &Router[T]{}
}

// Add registers a new handler for the given method and path.
func (router *Router[T]) Add(method string, path string, handler T) {
	tree := router.selectTree(method)
	tree.Add(path, handler)
}

// Lookup finds the handler and parameters for the given route.
func (router *Router[T]) Lookup(method string, path string) (T, []Parameter) {
	if method[0] == 'G' {
		return router.get.Lookup(path)
	}

	tree := router.selectTree(method)
	return tree.Lookup(path)
}

// LookupNoAlloc finds the handler and parameters for the given route without using any memory allocations.
func (router *Router[T]) LookupNoAlloc(method string, path string, addParameter func(string, string)) T {
	if method[0] == 'G' {
		return router.get.LookupNoAlloc(path, addParameter)
	}

	tree := router.selectTree(method)
	return tree.LookupNoAlloc(path, addParameter)
}

// Map traverses all trees and calls the given function on every node.
func (router *Router[T]) Map(transform func(T) T) {
	router.get.Map(transform)
	router.post.Map(transform)
	router.delete.Map(transform)
	router.put.Map(transform)
	router.patch.Map(transform)
	router.head.Map(transform)
	router.connect.Map(transform)
	router.trace.Map(transform)
	router.options.Map(transform)
}

// selectTree returns the tree by the given HTTP method.
func (router *Router[T]) selectTree(method string) *Tree[T] {
	switch method {
	case "GET":
		return &router.get
	case "POST":
		return &router.post
	case "DELETE":
		return &router.delete
	case "PUT":
		return &router.put
	case "PATCH":
		return &router.patch
	case "HEAD":
		return &router.head
	case "CONNECT":
		return &router.connect
	case "TRACE":
		return &router.trace
	case "OPTIONS":
		return &router.options
	default:
		return nil
	}
}

// Tree represents a radix tree.
type Tree[T any] struct {
	root treeNode[T]
}

// Add adds a new element to the tree.
func (tree *Tree[T]) Add(path string, data T) {
	// Search tree for equal parts until we can no longer proceed
	i := 0
	offset := 0
	node := &tree.root

	for {
	begin:
		switch node.kind {
		case parameter:
			// This only occurs when the same parameter based route is added twice.
			// node: /post/:id|
			// path: /post/:id|
			if i == len(path) {
				node.data = data
				return
			}

			// When we hit a separator, we'll search for a fitting child.
			if path[i] == separator {
				node, offset, _ = node.end(path, data, i, offset)
				goto next
			}

		default:
			if i == len(path) {
				// The path already exists.
				// node: /blog|
				// path: /blog|
				if i-offset == len(node.prefix) {
					node.data = data
					return
				}

				// The path ended but the node prefix is longer.
				// node: /blog|feed
				// path: /blog|
				node.split(i-offset, "", data)
				return
			}

			// The node we just checked is entirely included in our path.
			// node: /|
			// path: /|blog
			if i-offset == len(node.prefix) {
				var control flow
				node, offset, control = node.end(path, data, i, offset)

				switch control {
				case flowStop:
					return
				case flowBegin:
					goto begin
				case flowNext:
					goto next
				}
			}

			// We got a conflict.
			// node: /b|ag
			// path: /b|riefcase
			if path[i] != node.prefix[i-offset] {
				node.split(i-offset, path[i:], data)
				return
			}
		}

	next:
		i++
	}
}

// Lookup finds the data for the given path.
func (tree *Tree[T]) Lookup(path string) (T, []Parameter) {
	var params []Parameter

	data := tree.LookupNoAlloc(path, func(key string, value string) {
		params = append(params, Parameter{key, value})
	})

	return data, params
}

// LookupNoAlloc finds the data for the given path without using any memory allocations.
func (tree *Tree[T]) LookupNoAlloc(path string, addParameter func(key string, value string)) T {
	var (
		i             uint
		parameterPath string
		wildcardPath  string
		parameter     *treeNode[T]
		wildcard      *treeNode[T]
		node          = &tree.root
	)

	// Skip the first loop iteration if the starting characters are equal
	if len(path) > 0 && len(node.prefix) > 0 && path[0] == node.prefix[0] {
		i = 1
	}

begin:
	// Search tree for equal parts until we can no longer proceed
	for i < uint(len(path)) {
		// The node we just checked is entirely included in our path.
		// node: /|
		// path: /|blog
		if i == uint(len(node.prefix)) {
			if node.wildcard != nil {
				wildcard = node.wildcard
				wildcardPath = path[i:]
			}

			parameter = node.parameter
			parameterPath = path[i:]
			char := path[i]

			if char >= node.startIndex && char < node.endIndex {
				index := node.indices[char-node.startIndex]

				if index != 0 {
					node = node.children[index]
					path = path[i:]
					i = 1
					continue
				}
			}

			// node: /|:id
			// path: /|blog
			if node.parameter != nil {
				node = node.parameter
				path = path[i:]
				i = 1

				for i < uint(len(path)) {
					// node: /:id|/posts
					// path: /123|/posts
					if path[i] == separator {
						addParameter(node.prefix, path[:i])
						index := node.indices[separator-node.startIndex]
						node = node.children[index]
						path = path[i:]
						i = 1
						goto begin
					}

					i++
				}

				addParameter(node.prefix, path[:i])
				return node.data
			}

			// node: /|*any
			// path: /|image.png
			goto notFound
		}

		// We got a conflict.
		// node: /b|ag
		// path: /b|riefcase
		if path[i] != node.prefix[i] {
			goto notFound
		}

		i++
	}

	// node: /blog|
	// path: /blog|
	if i == uint(len(node.prefix)) {
		return node.data
	}

	// node: /|*any
	// path: /|image.png
notFound:
	if parameter != nil {
		addParameter(parameter.prefix, parameterPath)
		return parameter.data
	}

	if wildcard != nil {
		addParameter(wildcard.prefix, wildcardPath)
		return wildcard.data
	}

	var empty T
	return empty
}

// Map binds all handlers to a new one provided by the callback.
func (tree *Tree[T]) Map(transform func(T) T) {
	tree.root.each(func(node *treeNode[T]) {
		node.data = transform(node.data)
	})
}

// node types
const (
	separator = '/'
	parameter = ':'
	wildcard  = '*'
)

// treeNode represents a radix tree node.
type treeNode[T any] struct {
	prefix     string
	data       T
	children   []*treeNode[T]
	parameter  *treeNode[T]
	wildcard   *treeNode[T]
	indices    []uint8
	startIndex uint8
	endIndex   uint8
	kind       byte
}

// split splits the node at the given index and inserts
// a new child node with the given path and data.
// If path is empty, it will not create another child node
// and instead assign the data directly to the node.
func (node *treeNode[T]) split(index int, path string, data T) {
	// Create split node with the remaining string
	splitNode := node.clone(node.prefix[index:])

	// The existing data must be removed
	node.reset(node.prefix[:index])

	// If the path is empty, it means we don't create a 2nd child node.
	// Just assign the data for the existing node and store a single child node.
	if path == "" {
		node.data = data
		node.addChild(splitNode)
		return
	}

	node.addChild(splitNode)

	// Create new nodes with the remaining path
	node.append(path, data)
}

// clone clones the node with a new prefix.
func (node *treeNode[T]) clone(prefix string) *treeNode[T] {
	return &treeNode[T]{
		prefix:     prefix,
		data:       node.data,
		indices:    node.indices,
		startIndex: node.startIndex,
		endIndex:   node.endIndex,
		children:   node.children,
		parameter:  node.parameter,
		wildcard:   node.wildcard,
		kind:       node.kind,
	}
}

// reset resets the existing node data.
func (node *treeNode[T]) reset(prefix string) {
	var empty T
	node.prefix = prefix
	node.data = empty
	node.parameter = nil
	node.wildcard = nil
	node.kind = 0
	node.startIndex = 0
	node.endIndex = 0
	node.indices = nil
	node.children = nil
}

// addChild adds a child tree.
func (node *treeNode[T]) addChild(child *treeNode[T]) {
	if len(node.children) == 0 {
		node.children = append(node.children, nil)
	}

	firstChar := child.prefix[0]

	switch {
	case node.startIndex == 0:
		node.startIndex = firstChar
		node.indices = []uint8{0}
		node.endIndex = node.startIndex + uint8(len(node.indices))

	case firstChar < node.startIndex:
		diff := node.startIndex - firstChar
		newIndices := make([]uint8, diff+uint8(len(node.indices)))
		copy(newIndices[diff:], node.indices)
		node.startIndex = firstChar
		node.indices = newIndices
		node.endIndex = node.startIndex + uint8(len(node.indices))

	case firstChar >= node.endIndex:
		diff := firstChar - node.endIndex + 1
		newIndices := make([]uint8, diff+uint8(len(node.indices)))
		copy(newIndices, node.indices)
		node.indices = newIndices
		node.endIndex = node.startIndex + uint8(len(node.indices))
	}

	index := node.indices[firstChar-node.startIndex]

	if index == 0 {
		node.indices[firstChar-node.startIndex] = uint8(len(node.children))
		node.children = append(node.children, child)
		return
	}

	node.children[index] = child
}

// addTrailingSlash adds a trailing slash with the same data.
func (node *treeNode[T]) addTrailingSlash(data T) {
	if strings.HasSuffix(node.prefix, "/") || node.kind == wildcard || (separator >= node.startIndex && separator < node.endIndex && node.indices[separator-node.startIndex] != 0) {
		return
	}

	node.addChild(&treeNode[T]{
		prefix: "/",
		data:   data,
	})
}

// append appends the given path to the tree.
func (node *treeNode[T]) append(path string, data T) {
	// At this point, all we know is that somewhere
	// in the remaining string we have parameters.
	// node: /user|
	// path: /user|/:userid
	for {
		if path == "" {
			node.data = data
			return
		}

		paramStart := strings.IndexByte(path, parameter)

		if paramStart == -1 {
			paramStart = strings.IndexByte(path, wildcard)
		}

		// If it's a static route we are adding,
		// just add the remainder as a normal node.
		if paramStart == -1 {
			// If the node itself doesn't have a prefix (root node),
			// don't add a child and use the node itself.
			if node.prefix == "" {
				node.prefix = path
				node.data = data
				node.addTrailingSlash(data)
				return
			}

			child := &treeNode[T]{
				prefix: path,
				data:   data,
			}

			node.addChild(child)
			child.addTrailingSlash(data)
			return
		}

		// If we're directly in front of a parameter,
		// add a parameter node.
		if paramStart == 0 {
			paramEnd := strings.IndexByte(path, separator)

			if paramEnd == -1 {
				paramEnd = len(path)
			}

			child := &treeNode[T]{
				prefix: path[1:paramEnd],
				kind:   path[paramStart],
			}

			switch child.kind {
			case parameter:
				child.addTrailingSlash(data)
				node.parameter = child
				node = child
				path = path[paramEnd:]
				continue

			case wildcard:
				child.data = data
				node.wildcard = child
				return
			}
		}

		// We know there's a parameter, but not directly at the start.

		// If the node itself doesn't have a prefix (root node),
		// don't add a child and use the node itself.
		if node.prefix == "" {
			node.prefix = path[:paramStart]
			path = path[paramStart:]
			continue
		}

		// Add a normal node with the path before the parameter start.
		child := &treeNode[T]{
			prefix: path[:paramStart],
		}

		// Allow trailing slashes to return
		// the same content as their parent node.
		if child.prefix == "/" {
			child.data = node.data
		}

		node.addChild(child)
		node = child
		path = path[paramStart:]
	}
}

// end is called when the node was fully parsed
// and needs to decide the next control flow.
// end is only called from `tree.Add`.
func (node *treeNode[T]) end(path string, data T, i int, offset int) (*treeNode[T], int, flow) {
	char := path[i]

	if char >= node.startIndex && char < node.endIndex {
		index := node.indices[char-node.startIndex]

		if index != 0 {
			node = node.children[index]
			offset = i
			return node, offset, flowNext
		}
	}

	// No fitting children found, does this node even contain a prefix yet?
	// If no prefix is set, this is the starting node.
	if node.prefix == "" {
		node.append(path[i:], data)
		return node, offset, flowStop
	}

	// node: /user/|:id
	// path: /user/|:id/profile
	if node.parameter != nil && path[i] == parameter {
		node = node.parameter
		offset = i
		return node, offset, flowBegin
	}

	node.append(path[i:], data)
	return node, offset, flowStop
}

// each traverses the tree and calls the given function on every node.
func (node *treeNode[T]) each(callback func(*treeNode[T])) {
	callback(node)

	for _, child := range node.children {
		if child == nil {
			continue
		}

		child.each(callback)
	}

	if node.parameter != nil {
		node.parameter.each(callback)
	}

	if node.wildcard != nil {
		node.wildcard.each(callback)
	}
}

// Dynamic route management on Router
func (router *Router[T]) Remove(method string, path string) {
	tree := router.selectTree(method)
	if tree != nil {
		tree.Remove(path)
	}
}

func (router *Router[T]) Update(method string, path string, handler T) {
	router.Remove(method, path)
	router.Add(method, path, handler)
}

// Add a Remove method on Tree
func (tree *Tree[T]) Remove(path string) {
	// A minimal implementation: locate the node and reset its data.
	node := tree.lookupNode(path)
	if node != nil {
		var empty T
		node.data = empty
	}
}

// lookupNode performs a basic lookup returning the node pointer.
func (tree *Tree[T]) lookupNode(path string) *treeNode[T] {
	var (
		i    uint
		node = &tree.root
	)
	// skip initial matching if possible...
	if len(path) > 0 && len(node.prefix) > 0 && path[0] == node.prefix[0] {
		i = 1
	}
	for i < uint(len(path)) {
		// If we've exhausted this node's prefix, try checking its children.
		if i >= uint(len(node.prefix)) {
			matched := false
			for _, child := range node.children {
				if child != nil && strings.HasPrefix(path[i:], child.prefix) {
					node = child
					i += uint(len(child.prefix))
					matched = true
					break
				}
			}
			if !matched {
				return nil
			}
			continue
		}
		if path[i] != node.prefix[i] {
			return nil
		}
		i++
	}
	return node
}

// Implement Group routing

// Group wraps a common prefix.
type Group[T any] struct {
	prefix string
	router *Router[T]
}

func (r *Router[T]) Group(prefix string) *Group[T] {
	return &Group[T]{prefix: prefix, router: r}
}

// Group methods to add/remove/update routes using the group prefix.
func (g *Group[T]) Add(method, path string, handler T) {
	g.router.Add(method, g.prefix+path, handler)
}

func (g *Group[T]) Remove(method, path string) {
	g.router.Remove(method, g.prefix+path)
}

func (g *Group[T]) Update(method, path string, handler T) {
	g.router.Update(method, g.prefix+path, handler)
}
