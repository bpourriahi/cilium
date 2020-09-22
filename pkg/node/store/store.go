// Copyright 2018-2019 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package store

import (
	"context"
	"path"

	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"
)

var (
	// NodeStorePrefix is the kvstore prefix of the shared store
	//
	// WARNING - STABLE API: Changing the structure or values of this will
	// break backwards compatibility
	NodeStorePrefix = path.Join(kvstore.BaseKeyPrefix, "state", "nodes", "v1")

	// NodeRegisterStorePrefix is the kvstore prefix of the shared
	// store for node registration that will be followed by k8s
	// namespace name depending on agent's --k8s-namespace option
	//
	// WARNING - STABLE API: Changing the structure or values of this will
	// break backwards compatibility
	NodeRegisterStorePrefix = path.Join(kvstore.BaseKeyPrefix, "state", "noderegister", "v1")

	// KeyCreator creates a node for a shared store
	KeyCreator = func() store.Key {
		n := nodeTypes.Node{}
		return &n
	}
)

// NodeObserver implements the store.Observer interface and delegates update
// and deletion events to the node object itself.
type NodeObserver struct {
	manager NodeManager
}

// NewNodeObserver returns a new NodeObserver associated with the specified
// node manager
func NewNodeObserver(manager NodeManager) *NodeObserver {
	return &NodeObserver{manager: manager}
}

func (o *NodeObserver) OnUpdate(k store.Key) {
	if n, ok := k.(*nodeTypes.Node); ok {
		nodeCopy := n.DeepCopy()
		nodeCopy.Source = source.KVStore
		o.manager.NodeUpdated(*nodeCopy)
	}
}

func (o *NodeObserver) OnDelete(k store.NamedKey) {
	if n, ok := k.(*nodeTypes.Node); ok {
		nodeCopy := n.DeepCopy()
		nodeCopy.Source = source.KVStore
		o.manager.NodeDeleted(*nodeCopy)
	}
}

// NodeManager is the interface that the manager of nodes has to implement
type NodeManager interface {
	// NodeUpdated is called when the store detects a change in node
	// information
	NodeUpdated(n nodeTypes.Node)

	// NodeDeleted is called when the store detects a deletion of a node
	NodeDeleted(n nodeTypes.Node)

	// Exists is called to verify if a node exists
	Exists(id nodeTypes.Identity) bool
}

// NodeRegistrar is a wrapper around store.SharedStore.
type NodeRegistrar struct {
	*store.SharedStore

	registerStore *store.SharedStore
}

// RegisterNode registers the local node in the cluster
func (nr *NodeRegistrar) RegisterNode(n *nodeTypes.Node, manager NodeManager) error {
	if option.Config.KVStore == "" {
		return nil
	}

	// Join the shared store for node registrations
	registerStore, err := store.JoinSharedStore(store.Configuration{
		Prefix:     NodeRegisterStorePrefix,
		KeyCreator: KeyCreator,
	})
	if err != nil {
		return err
	}

	// Join the shared store holding node information of entire cluster
	store, err := store.JoinSharedStore(store.Configuration{
		Prefix:     NodeStorePrefix,
		KeyCreator: KeyCreator,
		Observer:   NewNodeObserver(manager),
	})

	if err != nil {
		registerStore.Release()
		return err
	}

	nr.registerStore = registerStore
	nr.SharedStore = store

	err = nr.UpdateLocalKeySync(n)
	if err != nil {
		registerStore.Release()
		nr.registerStore = nil
		store.Release()
		nr.SharedStore = nil
		return err
	}

	return nil
}

// UpdateLocalKeySync synchronizes the local key for the node using the
// SharedStore.
func (nr *NodeRegistrar) UpdateLocalKeySync(n *nodeTypes.Node) error {
	if nr.registerStore != nil {
		return nr.registerStore.UpdateLocalKeySync(context.TODO(), n)
	}
	return nr.SharedStore.UpdateLocalKeySync(context.TODO(), n)
}
