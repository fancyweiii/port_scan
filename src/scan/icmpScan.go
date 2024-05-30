package scan

type ICMPipAdd struct {
	Addresses []string
	Ports     []int
}

type ICMPScan interface {
	IcmpScanPort() ([]int, error)
}

func (ipa *ICMPipAdd) IcmpScanPort() ([]int, error) {

}
