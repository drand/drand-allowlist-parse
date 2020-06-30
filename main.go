package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/urfave/cli/v2"
)

const (
	// default file to read when none is provided.
	defaultFilename = "allowlist.txt"
)

func main() {
	app := &cli.App{
		Name:  "drand-allowlist-parse",
		Usage: "drand-allowlist-parse <allowlist.txt>",
		Description: `
This tool parses a drand allow-list, stripping out comments and blank
lines, verifying that all CIDRs are in the correct format and outputting
the resulting list in the preferred form (CSV, JSON, Text), so that it can
be easily re-used.`,
		Action: run,
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:  "ips",
				Usage: "list every individual IPs instead of CIDRs",
			},
			&cli.StringFlag{
				Name:  "format",
				Value: "csv",
				Usage: "format the list as: [csv, text, json]",
			},
		},
	}

	app.Run(os.Args)
}

func run(c *cli.Context) error {
	filename := c.Args().First()
	if filename == "" {
		filename = defaultFilename
	}

	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	ipnets := []*net.IPNet{}
	lineNumber := 0
	scanner := bufio.NewScanner(f)

	// Read every line.
	for scanner.Scan() {
		lineNumber++

		line := scanner.Text()
		// Get rid of spaces
		line = strings.Replace(line, " ", "", -1)

		// Skip comments and blank lines
		if len(line) == 0 || line[0] == '#' || line[0] == '/' {
			continue
		}

		// Parse the CIDR
		ip, ipnet, err := net.ParseCIDR(line)
		if err != nil {
			msg := fmt.Sprintf("%s:%d: Error parsing CIDR (%s): %s",
				filename, lineNumber, line, err)
			return cli.Exit(msg, 1)
		}

		// We only accept network addresses (i.e. 192.168.3.0/24 is
		// valid, 192.168.3.5/24 is not).
		if ip.String() != ipnet.IP.String() {
			msg := fmt.Sprintf("%s:%d: %s is not a valid network: should probably be %s",
				filename, lineNumber, line, ipnet)
			return cli.Exit(msg, 1)
		}

		ipnets = append(ipnets, ipnet)
	}

	if err := scanner.Err(); err != nil {
		return cli.Exit(err.Error(), 1)
	}

	results := []string{}
	if c.Bool("ips") {
		// List of
		for _, ipnet := range ipnets {
			results = append(results, ipsInNet(ipnet)...)
		}
	} else {
		for _, ipnet := range ipnets {
			results = append(results, ipnet.String())
		}
	}

	switch c.String("format") {
	case "csv":
		formatCSV(results)
	case "text":
		formatText(results)
	case "json":
		formatJSON(results)
	default:
		return cli.Exit("format not supported", 1)
	}
	return nil
}

// mostly copied from stackoverflow, of course.
func ipsInNet(ipnet *net.IPNet) []string {
	var ips []string

	// Note the only purpose of Mask is to make a copy of the IP byte
	// slice. In the original source it is use because it allows to
	// provide a CIDR that uses an arbitrary ip in the network, so the
	// mask provides the network IP.
	for ip := ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
		ips = append(ips, ip.String())
	}

	// Remove network address and broadcast address
	lenIPs := len(ips)
	switch {
	case lenIPs < 2:
		return ips

	default:
		return ips[1 : len(ips)-1]
	}
}

// Increases an IP address by one.
func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func formatCSV(results []string) {
	fmt.Println(strings.Join(results, ","))
}

func formatText(results []string) {
	fmt.Println(strings.Join(results, "\n"))
}

func formatJSON(results []string) {
	j, _ := json.Marshal(results)
	fmt.Println(string(j))
}
