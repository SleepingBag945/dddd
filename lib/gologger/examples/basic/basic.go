package main

import (
	"strconv"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
)

func main() {
	gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	//	gologger.DefaultLogger.SetFormatter(&formatter.JSON{})
	gologger.Print().Msgf("\tgologger: sample test\t\n")
	gologger.Info().Str("user", "pdteam").Msg("running simulation program")
	for i := 0; i < 10; i++ {
		gologger.Info().Str("count", strconv.Itoa(i)).Msg("running simulation step...")
	}
	gologger.Debug().Str("state", "running").Msg("planner running")
	gologger.Debug().TimeStamp().Str("state", "running").Msg("with timestamp event")
	gologger.Warning().Str("state", "errored").Str("status", "404").Msg("could not run")

	// with timestamp
	gologger.DefaultLogger.SetTimestamp(true, levels.LevelDebug)
	gologger.Debug().Msg("with automatic timestamp")
	gologger.Info().Msg("without automatic timestamp")

	gologger.Fatal().Msg("bye bye")
}
