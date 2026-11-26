//go:build ignore

// Command vlcheck validates LogsQL queries with the real VictoriaLogs parser.
// It is built inside a VictoriaLogs checkout (see .github/workflows/ci.yml):
// input lines are "<mode>\t<logsql>", mode R also checks that the query can
// be used with /select/logsql/stats_query_range.
package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/VictoriaMetrics/VictoriaLogs/lib/logstorage"
)

// reads "<label>\t<logsql>" lines; with prefix "R " also checks range-stats suitability
func main() {
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	bad := 0
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "\t", 3)
		mode, q := parts[0], parts[len(parts)-1]
		pq, err := logstorage.ParseQuery(q)
		if err != nil {
			bad++
			fmt.Printf("FAIL %s\n     %s\n     %v\n", mode, q, err)
			continue
		}
		if mode == "R" {
			if _, err := pq.GetStatsLabelsAddGroupingByTime(int64(60e9), 0); err != nil {
				bad++
				fmt.Printf("FAILRANGE %s\n     %v\n", q, err)
				continue
			}
		}
		fmt.Printf("ok   %s\n", pq.String())
	}
	if bad > 0 {
		os.Exit(1)
	}
}
