package main

import (
	"os"
	"strconv"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/formatter"
)

func main() {
	fname := "gologger.json"

	f, err := os.OpenFile(fname, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return
	}
	defer f.Close()
	teeformatter := formatter.NewTee(formatter.NewCLI(false), f)

	gologger.DefaultLogger.SetFormatter(teeformatter)

	// Do iterations
	gologger.Print().Msgf("\tgologger: sample test\t\n")
	gologger.Info().Str("user", "pdteam").Msg("running simulation program")
	for i := 0; i < 10; i++ {
		gologger.Info().Str("count", strconv.Itoa(i)).Msg("running simulation step...")
	}
	gologger.Debug().Str("state", "running").Msg("planner running")
	gologger.Warning().Str("state", "errored").Str("status", "404").Msg("could not run")
	gologger.Fatal().Msg("bye bye")
}
