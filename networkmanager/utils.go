package networkmanager

import (
	"net"
	"reflect"
	"syscall"

	"github.com/aoscloud/aos_common/aoserrors"
	"github.com/vishvananda/netlink"
)

func checkExistNetInterface(name string) (ipNet *net.IPNet, err error) {
	netInterface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, aoserrors.Errorf("unable to find interface %s", err)
	}

	addrs, err := netInterface.Addrs()
	if err != nil {
		return nil, aoserrors.Errorf("interface has no address %s", err)
	}

	for _, addr := range addrs {
		switch v := addr.(type) {
		case *net.IPNet:
			if ipv4 := v.IP.To4(); ipv4 != nil {
				_, ipSubnet, _ := net.ParseCIDR(v.String())
				return ipSubnet, nil
			}

		default:
			return nil, aoserrors.Errorf("unsupported key type: %v", reflect.TypeOf(v))
		}
	}

	return nil, aoserrors.Errorf("interface has not IPv4 address")
}

func getNetworkRoutes() (routeIPList []netlink.Route, err error) {
	initNl, err := netlink.NewHandle(syscall.NETLINK_ROUTE, syscall.NETLINK_NETFILTER)
	if err != nil {
		return nil, aoserrors.Errorf("could not create netlink handle on initial namespace: %v", err)
	}

	defer initNl.Delete()

	routeIPList, err = initNl.RouteList(nil, netlink.FAMILY_V4)
	if err != nil {
		return nil, aoserrors.Wrap(err)
	}

	return routeIPList, nil
}

func checkRouteOverlaps(toCheck *net.IPNet, networks []netlink.Route) (overlapsIPs bool) {
	for _, network := range networks {
		if network.Dst != nil && (toCheck.Contains(network.Dst.IP) || network.Dst.Contains(toCheck.IP)) {
			return true
		}
	}

	return false
}
