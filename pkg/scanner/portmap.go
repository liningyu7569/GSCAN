package scanner

import "syscall"

const (
	ProtocolTCP  = syscall.IPPROTO_TCP
	ProtocolUDP  = syscall.IPPROTO_UDP
	ProtocolSCTP = syscall.IPPROTO_SCTP
	ProtocolIP   = syscall.IPPROTO_IP
	ProtocolICMP = 1
)

// TopPorts 包含了互联网上最常见的端口，按频率排序
var TopPorts = []int{
	80, 23, 443, 21, 22, 25, 3389, 110, 445, 139, 143, 53, 135, 3306, 8080, 1723, 111,
	995, 993, 5900, 1025, 587, 8888, 199, 1720, 465, 548, 113, 81, 6001, 10000, 514,
	5060, 179, 1026, 2000, 8443, 8000, 32768, 554, 26, 1433, 49152, 2001, 515, 8008,
	49154, 1027, 5666, 646, 5000, 5631, 631, 49153, 8081, 2049, 88, 79, 5800, 106,
	2121, 1110, 49155, 6000, 513, 990, 5357, 427, 49156, 5432, 544, 5101, 144, 7,
	389, 8009, 3128, 444, 9999, 5009, 7070, 5190, 3000, 5431, 1900, 3986, 13, 1029,
	9, 5051, 6646, 49157, 1028, 873, 1755, 2717, 4899, 9100, 119, 37,
}

// topPortsMap 用于 O(1) 复杂度的查找
var topPortsMap map[int]struct{}

// init 函数在包加载时自动执行，初始化 map
func init() {
	topPortsMap = make(map[int]struct{}, len(TopPorts))
	for _, p := range TopPorts {
		topPortsMap[p] = struct{}{}
	}
}

// IsTopPort 快速检查是否为热门端口，时间复杂度为 O(1)
func IsTopPort(port int) bool {
	_, ok := topPortsMap[port]
	return ok
}

type SingleProtocolMap struct {
	//65536大数组
	Lookup []int
	//顺序存储扫描端口
	List []int
}

type MultiProtocolMap struct {
	Maps map[int]*SingleProtocolMap
}

var GlobalPorts = &MultiProtocolMap{
	Maps: make(map[int]*SingleProtocolMap),
}

func (m *MultiProtocolMap) Initialize(ports []int, protocol int) {
	m.Maps[protocol] = NewSingleProtocolMap(ports)
}

// 构建端口数组
func NewSingleProtocolMap(ports []int) *SingleProtocolMap {
	lookup := make([]int, 65536)
	for i := range lookup {
		lookup[i] = -1
	}
	//空间映射存储端口，O1
	for index, port := range ports {
		if port > 65535 || port < 0 {
			continue
		}
		lookup[port] = index
	}
	return &SingleProtocolMap{
		Lookup: lookup,
		List:   ports,
	}
}

func (pm *SingleProtocolMap) IsScanned(port int) bool {
	if port < 0 || port > 65535 {
		return false
	}
	return pm.Lookup[port] != -1
}

// O1获取扫描端口的下标
func (pm *SingleProtocolMap) GetIndex(port int) int {
	if port < 0 || port > 65535 {
		return -1
	}
	return pm.Lookup[port]
}

// 获取下标对应端口
func (pm *SingleProtocolMap) GetPort(index int) int {
	if index < 0 || index > len(pm.List) {
		return -1
	}
	return pm.List[index]
}
func (pm *SingleProtocolMap) Count() int {
	if pm == nil {
		return 0
	}
	return len(pm.List)
}
