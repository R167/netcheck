package checkers

import (
	"github.com/R167/netcheck/checkers/common"
	"github.com/R167/netcheck/checkers/ports"
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
		web.NewWebChecker(),
		ports.NewPortsChecker(),
		upnp.NewUPnPChecker(),
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