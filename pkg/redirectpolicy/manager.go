//  Copyright 2020 Authors of Cilium
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

package redirectpolicy

import (
	"fmt"
	"net"

	"github.com/cilium/cilium/pkg/k8s"
	slimcorev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/core/v1"
	k8sUtils "github.com/cilium/cilium/pkg/k8s/utils"
	lb "github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	serviceStore "github.com/cilium/cilium/pkg/service/store"
	"github.com/cilium/cilium/pkg/u8proto"

	"github.com/sirupsen/logrus"
	"k8s.io/client-go/tools/cache"
)

var (
	log                 = logging.DefaultLogger.WithField(logfields.LogSubsys, "redirectpolicy")
	localRedirectSvcStr = "-local-redirect"
)

type svcManager interface {
	DeleteService(frontend lb.L3n4Addr) (bool, error)
	UpsertService(*lb.SVC) (bool, lb.ID, error)
}

// podID is pod name and namespace
type podID = k8s.ServiceID

// Manager manages configurations related to Local Redirect Policies
// that enable redirecting traffic from the specified frontend to a set of node-local
// backend pods selected based on the backend configuration. To do that, it keeps
// track of add/delete events for resources like LRP, Pod and Service.
// For every local redirect policy configuration, it creates a
// new lb.SVCTypeLocalRedirect service with a frontend that has at least one node-local backend.
type Manager struct {
	// Service handler to manage service entries corresponding to redirect policies
	svcManager svcManager

	// Mutex to protect against concurrent access to the maps
	mutex lock.RWMutex

	// Stores mapping of all the current redirect policy frontend to their
	// respective policies
	// Frontends are namespace agnostic
	policyFrontendsByHash map[string]policyID
	// Stores mapping of redirect policy serviceID to the corresponding policyID for
	// easy lookup in policyConfigs
	policyServices map[k8s.ServiceID]policyID
	// Stores mapping of podID to redirect policies that select this pod along
	// with derived pod backends
	policyPods map[podID][]podPolicyInfo
	// Stores redirect policy configs indexed by policyID
	policyConfigs map[policyID]*LRPConfig
}

func NewRedirectPolicyManager(svc svcManager) *Manager {
	return &Manager{
		svcManager:            svc,
		policyFrontendsByHash: make(map[string]policyID),
		policyServices:        make(map[k8s.ServiceID]policyID),
		policyPods:            make(map[podID][]podPolicyInfo),
		policyConfigs:         make(map[policyID]*LRPConfig),
	}
}

// Event handlers

// AddRedirectPolicy parses the given local redirect policy config, and updates
// internal state with the config fields.
func (rpm *Manager) AddRedirectPolicy(config LRPConfig, svcCache *k8s.ServiceCache, podStore cache.Store) (bool, error) {
	rpm.mutex.Lock()
	defer rpm.mutex.Unlock()

	_, ok := rpm.policyConfigs[config.id]
	if ok {
		// TODO Existing policy update
		log.Warn("Local redirect policy updates are not handled")
		return true, nil
	}

	err := rpm.isValidConfig(config)
	if err != nil {
		return false, err
	}

	// New redirect policy
	rpm.storePolicyConfig(config)

	switch config.lrpType {
	case lrpConfigTypeAddr:
		log.WithFields(logrus.Fields{
			logfields.K8sNamespace:             config.id.Namespace,
			logfields.LRPName:                  config.id.Name,
			logfields.LRPFrontends:             config.frontendMappings,
			logfields.LRPLocalEndpointSelector: config.backendSelector,
			logfields.LRPBackendPorts:          config.backendPorts,
		}).Debug("Add local redirect policy")
		pods := rpm.getLocalPodsForPolicy(&config, podStore)
		if len(pods) == 0 {
			return true, nil
		}
		rpm.upsertConfig(&config, pods...)

	case lrpConfigTypeSvc:
		log.WithFields(logrus.Fields{
			logfields.K8sNamespace:             config.id.Namespace,
			logfields.LRPName:                  config.id.Name,
			logfields.K8sSvcID:                 config.serviceID,
			logfields.LRPFrontends:             config.frontendMappings,
			logfields.LRPLocalEndpointSelector: config.backendSelector,
			logfields.LRPBackendPorts:          config.backendPorts,
		}).Debug("Add local redirect policy")

		rpm.getAndUpsertPolicySvcConfig(&config, svcCache, podStore)
	}

	return true, nil
}

// DeleteRedirectPolicy deletes the internal state associated with the given policy.
func (rpm *Manager) DeleteRedirectPolicy(config LRPConfig) error {
	rpm.mutex.Lock()
	defer rpm.mutex.Unlock()

	storedConfig := rpm.policyConfigs[config.id]
	if storedConfig == nil {
		return fmt.Errorf("local redirect policy to be deleted not found")
	}
	log.WithFields(logrus.Fields{"policyID": config.id}).
		Debug("Delete local redirect policy")

	switch storedConfig.lrpType {
	case lrpConfigTypeSvc:
		rpm.deletePolicyService(*storedConfig.serviceID)
	case lrpConfigTypeAddr:
		for _, feM := range storedConfig.frontendMappings {
			rpm.deletePolicyFrontend(storedConfig, feM.feAddr)
		}
	}

	for p, pp := range rpm.policyPods {
		var newPolicyList []podPolicyInfo
		for _, info := range pp {
			if info.policyID != storedConfig.id {
				newPolicyList = append(newPolicyList, info)
			}
		}
		if len(newPolicyList) > 0 {
			rpm.policyPods[p] = newPolicyList
		} else {
			delete(rpm.policyPods, p)
		}
	}
	rpm.deletePolicyConfig(storedConfig)
	return nil
}

// OnAddService handles Kubernetes service (clusterIP type) add events, and
// updates the internal state for the policy config associated with the service.
func (rpm *Manager) OnAddService(svcID k8s.ServiceID, svcCache *k8s.ServiceCache, podStore cache.Store) {
	rpm.mutex.Lock()
	defer rpm.mutex.Unlock()
	if len(rpm.policyConfigs) == 0 {
		return
	}

	// Check if this service is selected by any of the current policies.
	if id, ok := rpm.policyServices[svcID]; ok {
		// TODO Add unit test to assert lrpConfigType among other things.
		config := rpm.policyConfigs[id]
		if !config.checkNamespace(svcID.Namespace) {
			return
		}
		rpm.getAndUpsertPolicySvcConfig(config, svcCache, podStore)
	}
}

// OnDeleteService handles Kubernetes service deletes, and deletes the internal state
// for the policy config that might be associated with the service.
func (rpm *Manager) OnDeleteService(svcID k8s.ServiceID) {
	rpm.mutex.Lock()
	defer rpm.mutex.Unlock()
	if len(rpm.policyConfigs) == 0 {
		return
	}

	rpm.deletePolicyService(svcID)
}

func (rpm *Manager) OnAddPod(pod *slimcorev1.Pod) {
	rpm.mutex.Lock()
	defer rpm.mutex.Unlock()

	if len(rpm.policyConfigs) == 0 {
		return
	}
	// If the pod already exists in the internal cache, ignore all the subsequent
	// events since they'll be handled in the OnUpdatePod callback.
	// GH issue #13136
	// TODO add unit test
	id := k8s.ServiceID{
		Name:      pod.GetName(),
		Namespace: pod.GetNamespace(),
	}
	if _, ok := rpm.policyPods[id]; ok {
		return
	}
	rpm.OnUpdatePodLocked(pod)
}

func (rpm *Manager) OnUpdatePodLocked(pod *slimcorev1.Pod) {
	if len(rpm.policyConfigs) == 0 {
		return
	}

	podIPs, err := k8sUtils.ValidIPs(pod.Status)
	if err != nil {
		return
	}
	podData := rpm.getPodMetadata(pod, podIPs)

	// Check if the pod was previously selected by any of the policies.
	if policies, ok := rpm.policyPods[podData.id]; ok {
		for _, podInfo := range policies {
			config := rpm.policyConfigs[podInfo.policyID]
			rpm.deletePolicyBackends(config, podInfo.backends...)
		}
	}
	// Check if any of the current redirect policies select this pod.
	for _, config := range rpm.policyConfigs {
		if config.policyConfigSelectsPod(podData) {
			rpm.upsertConfig(config, podData)
		}
	}
}

func (rpm *Manager) OnUpdatePod(pod *slimcorev1.Pod) {
	rpm.mutex.Lock()
	defer rpm.mutex.Unlock()
	// TODO add unit test to validate that we get callbacks only for relevant events
	rpm.OnUpdatePodLocked(pod)
}

func (rpm *Manager) OnDeletePod(pod *slimcorev1.Pod) {
	rpm.mutex.Lock()
	defer rpm.mutex.Unlock()
	if len(rpm.policyConfigs) == 0 {
		return
	}
	id := k8s.ServiceID{
		Name:      pod.GetName(),
		Namespace: pod.GetNamespace(),
	}

	if policies, ok := rpm.policyPods[id]; ok {
		for _, podInfo := range policies {
			config := rpm.policyConfigs[podInfo.policyID]
			rpm.deletePolicyBackends(config, podInfo.backends...)
		}
		delete(rpm.policyPods, id)
	}
}

// podPolicyInfo stores information about the policy that selects the pod and pod backend(s)
type podPolicyInfo struct {
	policyID policyID
	backends []backend
}

// podMetadata stores relevant metadata associated with a pod that's updated during pod
// add/update events
type podMetadata struct {
	labels map[string]string
	// id the pod's name and namespace
	id podID
	// ips are pod's unique IPs
	ips []string
	// namedPorts stores pod port and protocol indexed by the port name
	namedPorts serviceStore.PortConfiguration
}

// Note: Following functions need to be called with the redirect policy manager lock.

// getAndUpsertPolicySvcConfig gets service frontends for the given config service
// and upserts the service frontends.
func (rpm *Manager) getAndUpsertPolicySvcConfig(config *LRPConfig, svcCache *k8s.ServiceCache, podStore cache.Store) {
	var svcFrontends []*frontend
	switch config.frontendType {
	case svcFrontendAll:
		// Get all the service frontends.
		addrsByPort := svcCache.GetServiceAddrsWithType(*config.serviceID,
			lb.SVCTypeClusterIP)
		config.frontendMappings = make([]*feMapping, 0, len(addrsByPort))
		for p, addr := range addrsByPort {
			feM := &feMapping{
				feAddr: addr,
				fePort: string(p),
			}
			config.frontendMappings = append(config.frontendMappings, feM)
			svcFrontends = append(svcFrontends, addr)
		}
		for _, addr := range svcFrontends {
			rpm.updateConfigSvcFrontend(config, addr)
		}

	case svcFrontendSinglePort:
		// Get service frontend with the clusterIP and the policy config (unnamed) port.
		ip := svcCache.GetServiceFrontendIP(*config.serviceID, lb.SVCTypeClusterIP)
		config.frontendMappings[0].feAddr.IP = ip
		rpm.updateConfigSvcFrontend(config, config.frontendMappings[0].feAddr)

	case svcFrontendNamedPorts:
		// Get service frontends with the clusterIP and the policy config named ports.
		ports := make([]string, len(config.frontendMappings))
		for i, mapping := range config.frontendMappings {
			ports[i] = mapping.fePort
		}
		ip := svcCache.GetServiceFrontendIP(*config.serviceID, lb.SVCTypeClusterIP)
		for _, feM := range config.frontendMappings {
			feM.feAddr.IP = ip
			svcFrontends = append(svcFrontends, feM.feAddr)
		}
		for _, addr := range svcFrontends {
			rpm.updateConfigSvcFrontend(config, addr)
		}
	}

	pods := rpm.getLocalPodsForPolicy(config, podStore)
	if len(pods) > 0 {
		rpm.upsertConfig(config, pods...)
	}

}

// storePolicyConfig stores various state for the given policy config.
func (rpm *Manager) storePolicyConfig(config LRPConfig) {
	rpm.policyConfigs[config.id] = &config

	switch config.lrpType {
	case lrpConfigTypeAddr:
		for _, feM := range config.frontendMappings {
			rpm.policyFrontendsByHash[feM.feAddr.Hash()] = config.id
		}
	case lrpConfigTypeSvc:
		rpm.policyServices[*config.serviceID] = config.id
	}
}

// deletePolicyConfig cleans up stored state for the given policy config.
func (rpm *Manager) deletePolicyConfig(config *LRPConfig) {
	switch config.lrpType {
	case lrpConfigTypeAddr:
		for _, feM := range config.frontendMappings {
			delete(rpm.policyFrontendsByHash, feM.feAddr.Hash())
		}
	case lrpConfigTypeSvc:
		delete(rpm.policyServices, *config.serviceID)
	}
	delete(rpm.policyConfigs, config.id)
}

func (rpm *Manager) updateConfigSvcFrontend(config *LRPConfig, frontends ...*frontend) {
	for _, f := range frontends {
		rpm.policyFrontendsByHash[f.Hash()] = config.id
	}
	rpm.policyConfigs[config.id] = config
}

func (rpm *Manager) filterBackends(fe *feMapping, backends ...backend) []backend {
	var newBackends []backend
	for _, currBk := range fe.backends {
		for _, removeBk := range backends {
			if removeBk.StringWithProtocol() != currBk.StringWithProtocol() {
				newBackends = append(newBackends, currBk)
			}
		}
	}
	return newBackends
}

func (rpm *Manager) deletePolicyBackends(config *LRPConfig, backends ...backend) {
	// Currently, we expect number of LRP backends to be a single digit number.
	// If this scales up, we might need to optimize this using sets.
	for _, fe := range config.frontendMappings {
		fe.backends = rpm.filterBackends(fe, backends...)
		rpm.notifyPolicyBackendDelete(config, fe)
	}
}

// Deletes service entry for the specified frontend.
func (rpm *Manager) deletePolicyFrontend(config *LRPConfig, frontend *frontend) {
	found, err := rpm.svcManager.DeleteService(*frontend)
	delete(rpm.policyFrontendsByHash, frontend.Hash())
	if !found || err != nil {
		log.WithError(err).Debugf("Local redirect service for policy %v not deleted",
			config.id)
	}
}

// Updates service manager with the new set of backends now configured in 'config'.
func (rpm *Manager) notifyPolicyBackendDelete(config *LRPConfig, frontendMapping *feMapping) {
	if len(frontendMapping.backends) > 0 {
		rpm.upsertService(config, frontendMapping)
	} else {
		// No backends so remove the service entry.
		found, err := rpm.svcManager.DeleteService(*frontendMapping.feAddr)
		if !found || err != nil {
			log.WithError(err).Errorf("Local redirect service for policy (%v)"+
				" with frontend (%v) not deleted", config.id, frontendMapping.feAddr)
		}
	}
}

// deletePolicyService deletes internal state associated with the specified service.
func (rpm *Manager) deletePolicyService(svcID k8s.ServiceID) {
	if rp, ok := rpm.policyServices[svcID]; ok {
		// Get the policy config that selects this service.
		config := rpm.policyConfigs[rp]
		for _, m := range config.frontendMappings {
			rpm.deletePolicyFrontend(config, m.feAddr)
			switch config.frontendType {
			case svcFrontendAll:
				config.frontendMappings = nil
			case svcFrontendSinglePort:
				fallthrough
			case svcFrontendNamedPorts:
				for _, feM := range config.frontendMappings {
					feM.feAddr.IP = net.IP{}
				}
			}
		}
	}
}

// upsertService upserts a service entry for the given policy config that's ready.
func (rpm *Manager) upsertService(config *LRPConfig, frontendMapping *feMapping) {
	frontendAddr := lb.L3n4AddrID{
		L3n4Addr: *frontendMapping.feAddr,
		ID:       lb.ID(0),
	}
	var backendAddrs []lb.Backend
	for _, be := range frontendMapping.backends {
		backendAddrs = append(backendAddrs, lb.Backend{
			NodeName: nodeTypes.GetName(),
			L3n4Addr: be,
		})
	}
	p := &lb.SVC{
		Name:          config.id.Name + localRedirectSvcStr,
		Namespace:     config.id.Namespace,
		Type:          lb.SVCTypeLocalRedirect,
		Frontend:      frontendAddr,
		Backends:      backendAddrs,
		TrafficPolicy: lb.SVCTrafficPolicyCluster,
	}

	if _, _, err := rpm.svcManager.UpsertService(p); err != nil {
		log.WithError(err).Error("Error while inserting service in LB map")
	}
}

// Returns a slice of endpoint pods metadata that are selected by the given policy config.
func (rpm *Manager) getLocalPodsForPolicy(config *LRPConfig, podStore cache.Store) []*podMetadata {
	var retPods []*podMetadata

	for _, podItem := range podStore.List() {
		pod, ok := podItem.(*slimcorev1.Pod)
		if !ok || !config.checkNamespace(pod.GetNamespace()) {
			continue
		}
		podIPs, err := k8sUtils.ValidIPs(pod.Status)
		if err != nil {
			continue
		}
		podInfo := rpm.getPodMetadata(pod, podIPs)
		if !config.policyConfigSelectsPod(podInfo) {
			continue
		}
		retPods = append(retPods, podInfo)
	}

	return retPods
}

// isValidConfig validates the given policy config for duplicates.
// Note: The config is already sanitized.
func (rpm *Manager) isValidConfig(config LRPConfig) error {
	switch config.lrpType {
	case lrpConfigTypeAddr:
		for _, feM := range config.frontendMappings {
			fe := feM.feAddr
			id, ok := rpm.policyFrontendsByHash[fe.Hash()]
			if ok && config.id.Name != id.Name {
				return fmt.Errorf("CiliumLocalRedirectPolicy for"+
					"frontend %v already exists : %v", fe, config.id.Name)
			}
		}

	case lrpConfigTypeSvc:
		p, ok := rpm.policyServices[*config.serviceID]
		// Only 1 serviceMatcher policy is allowed for a service name within a namespace.
		if ok && config.id.Namespace != "" &&
			config.id.Namespace == rpm.policyConfigs[p].id.Namespace {
			return fmt.Errorf("CiliumLocalRedirectPolicy for"+
				" service %v already exists in namespace %v", config.serviceID,
				config.id.Namespace)
		}
	}

	return nil
}

func (rpm *Manager) upsertConfig(config *LRPConfig, pods ...*podMetadata) {
	switch config.frontendType {
	case svcFrontendSinglePort:
		fallthrough
	case addrFrontendSinglePort:
		rpm.upsertConfigWithSinglePort(config, pods...)
	case svcFrontendNamedPorts:
		fallthrough
	case addrFrontendNamedPorts:
		rpm.upsertConfigWithNamedPorts(config, pods...)
	case svcFrontendAll:
		if len(config.frontendMappings) > 1 {
			// The retrieved service frontend has multiple ports, in which case
			// Kubernetes mandates that the ports be named.
			rpm.upsertConfigWithNamedPorts(config, pods...)
		} else {
			// The retrieved service frontend has only 1 port, in which case
			// port names are optional.
			rpm.upsertConfigWithSinglePort(config, pods...)
		}
	}
}

// upsertConfigWithSinglePort upserts a policy config frontend with the corresponding
// backends.
// Frontend <ip, port, protocol> is mapped to backend <ip, port, protocol> entry.
// If a pod has multiple IPs, then there will be multiple backend entries created
// for the pod with common <port, protocol>.
func (rpm *Manager) upsertConfigWithSinglePort(config *LRPConfig, pods ...*podMetadata) {
	var bes4 []backend
	var bes6 []backend

	// Generate and map pod backends to the policy frontend. The policy config
	// is already sanitized, and has matching backend and frontend port protocol.
	// We currently don't check which backends are updated before upserting a
	// a service with the corresponding frontend. This can be optimized when LRPs
	// are scaled up.
	bePort := config.backendPorts[0]
	feM := config.frontendMappings[0]
	for _, pod := range pods {
		for _, ip := range pod.ips {
			beIP := net.ParseIP(ip)
			if beIP == nil {
				continue
			}
			be := backend{
				IP: net.ParseIP(ip),
				L4Addr: lb.L4Addr{
					Protocol: bePort.l4Addr.Protocol,
					Port:     bePort.l4Addr.Port,
				},
			}
			if feM.feAddr.IP.To4() != nil {
				if option.Config.EnableIPv4 {
					bes4 = append(bes4, be)
				}
			} else {
				if option.Config.EnableIPv6 {
					bes6 = append(bes6, be)
				}
			}
		}
		if len(bes4) > 0 {
			rpm.upsertServiceWithBackends(config, feM, pod.id, bes4)
		} else if len(bes6) > 0 {
			rpm.upsertServiceWithBackends(config, feM, pod.id, bes6)
		}
	}
	return
}

// upsertConfigWithNamedPorts upserts policy config frontends to the corresponding
// backends matched by port names.
func (rpm *Manager) upsertConfigWithNamedPorts(config *LRPConfig, pods ...*podMetadata) {
	// Generate backends for the policy config's backend named ports, and then
	// map the backends to policy frontends based on the named ports.
	// We currently don't check which backends are updated before upserting a
	// a service with the corresponding frontend. This can be optimized if LRPs
	// are scaled up.
	for _, feM := range config.frontendMappings {
		namedPort := feM.fePort
		var (
			bes4   []backend
			bes6   []backend
			bePort *bePortInfo
			ok     bool
		)
		if bePort, ok = config.backendPortsByPortName[namedPort]; !ok {
			// The frontend named port not found in the backend ports map.
			continue
		}
		for _, pod := range pods {
			if _, ok = pod.namedPorts[namedPort]; ok {
				// Generate pod backends.
				for _, ip := range pod.ips {
					beIP := net.ParseIP(ip)
					if beIP == nil || bePort.l4Addr.Protocol != feM.feAddr.Protocol {
						continue
					}
					be := backend{
						IP: net.ParseIP(ip),
						L4Addr: lb.L4Addr{
							Protocol: bePort.l4Addr.Protocol,
							Port:     bePort.l4Addr.Port,
						},
					}
					if feM.feAddr.IP.To4() != nil {
						if option.Config.EnableIPv4 {
							bes4 = append(bes4, be)
						}
					} else {
						if option.Config.EnableIPv6 {
							bes6 = append(bes6, be)
						}
					}
				}
			}
			if len(bes4) > 0 {
				rpm.upsertServiceWithBackends(config, feM, pod.id, bes4)
			} else if len(bes6) > 0 {
				rpm.upsertServiceWithBackends(config, feM, pod.id, bes6)
			}
		}
	}
}

// upsertServiceWithBackends updates policy config internal state and upserts
// service with the given pod backends.
func (rpm *Manager) upsertServiceWithBackends(config *LRPConfig, frontendMapping *feMapping, podID podID, backends []backend) {
	frontendMapping.backends = backends
	rpm.policyPods[podID] = append(rpm.policyPods[podID], podPolicyInfo{
		policyID: config.id,
		backends: backends,
	})
	rpm.upsertService(config, frontendMapping)
}

// TODO This function along with podMetadata can potentially be removed. We
// can directly reference the relevant pod metedata on-site.
func (rpm *Manager) getPodMetadata(pod *slimcorev1.Pod, podIPs []string) *podMetadata {
	namedPorts := make(serviceStore.PortConfiguration)
	for _, container := range pod.Spec.Containers {
		for _, port := range container.Ports {
			if port.Name == "" {
				continue
			}
			_, err := u8proto.ParseProtocol(string(port.Protocol))
			if err != nil {
				return nil
			}
			if port.ContainerPort < 1 || port.ContainerPort > 65535 {
				return nil
			}
			namedPorts[port.Name] = lb.NewL4Addr(lb.L4Type(port.Protocol), uint16(port.ContainerPort))
		}
	}
	return &podMetadata{
		ips:        podIPs,
		labels:     pod.GetLabels(),
		namedPorts: namedPorts,
		id: k8s.ServiceID{
			Name:      pod.GetName(),
			Namespace: pod.GetNamespace(),
		},
	}
}
