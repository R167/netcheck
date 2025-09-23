package checkers

import (
	"github.com/R167/netcheck/checkers/api"
	"github.com/R167/netcheck/checkers/common"
	"github.com/R167/netcheck/checkers/device"
	"github.com/R167/netcheck/checkers/external"
	"github.com/R167/netcheck/checkers/ipv6"
	"github.com/R167/netcheck/checkers/lldp"
	"github.com/R167/netcheck/checkers/mdns"
	"github.com/R167/netcheck/checkers/natpmp"
	"github.com/R167/netcheck/checkers/ports"
	"github.com/R167/netcheck/checkers/routes"
	"github.com/R167/netcheck/checkers/ssdp"
	"github.com/R167/netcheck/checkers/starlink"
	"github.com/R167/netcheck/checkers/upnp"
	"github.com/R167/netcheck/checkers/web"
	"github.com/R167/netcheck/internal/checker"
)

type CheckInfo struct {
	Checker        checker.Checker
	Flag           *bool
	RequiresRouter bool
	DefaultEnabled bool
}

func AllCheckers() []checker.Checker {
	return []checker.Checker{
		// Router-based checkers (require router access)
		web.NewWebChecker(),
		ports.NewPortsChecker(),
		upnp.NewUPnPChecker(),
		natpmp.NewNATpmpChecker(),
		ipv6.NewIPv6Checker(),
		mdns.NewMDNSChecker(),
		ssdp.NewSSDPChecker(),
		api.NewAPIChecker(),
		starlink.NewStarlinkChecker(),

		// Standalone checkers (don't require router access)
		routes.NewRoutesChecker(),
		device.NewDeviceChecker(),
		external.NewExternalChecker(),
		lldp.NewLLDPChecker(),
	}
}

func GetChecker(name string) checker.Checker {
	for _, c := range AllCheckers() {
		if c.Name() == name {
			return c
		}
	}
	return nil
}

func RunChecker(name string, config checker.CheckerConfig, router *common.RouterInfo) {
	c := GetChecker(name)
	if c != nil && c.RequiresRouter() {
		c.Run(config, router)
	}
}

func RunStandaloneChecker(name string, config checker.CheckerConfig) {
	c := GetChecker(name)
	if c != nil && !c.RequiresRouter() {
		c.RunStandalone(config)
	}
}

// GetCheckInfo returns checker info with associated flag
func GetCheckInfo(c checker.Checker, flags map[string]*bool) CheckInfo {
	flagName := c.Name()
	return CheckInfo{
		Checker:        c,
		Flag:           flags[flagName],
		RequiresRouter: c.RequiresRouter(),
		DefaultEnabled: c.DefaultEnabled(),
	}
}
