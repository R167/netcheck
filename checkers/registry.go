package checkers

import (
	"github.com/R167/netcheck/checkers/common"
	"github.com/R167/netcheck/checkers/ports"
	"github.com/R167/netcheck/checkers/upnp"
	"github.com/R167/netcheck/checkers/web"
	"github.com/R167/netcheck/internal/checker"
)

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