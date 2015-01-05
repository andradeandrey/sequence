// Copyright (c) 2014 Dataence, LLC. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime/pprof"
	"strings"
	"sync/atomic"
	"time"

	"github.com/dataence/glog"
	"github.com/spf13/cobra"
	"github.com/surge/sequence"
)

var (
	sequenceCmd = &cobra.Command{
		Use:   "sequence",
		Short: "sequence is a sequenceial semantic log analyzer and analyzer",
	}

	scanCmd = &cobra.Command{
		Use:   "scan",
		Short: "scan will tokenize a log file or message and output a list of tokens",
	}

	analyzeCmd = &cobra.Command{
		Use:   "analyze",
		Short: "analyze will analyze a log file and output a list of patterns that will match all the log messages",
	}

	parseCmd = &cobra.Command{
		Use:   "parse",
		Short: "parse will parse a log file and output a list of parsed tokens for each of the log messages",
	}

	benchCmd = &cobra.Command{
		Use:   "bench",
		Short: "benchmark the parsing of a log file, no output is provided",
	}

	inmsg      string
	infile     string
	outfile    string
	patfile    string
	cpuprofile string
	workers    int

	quit chan struct{}
	done chan struct{}
)

func init() {
	quit = make(chan struct{})
	done = make(chan struct{})

	scanCmd.Flags().StringVarP(&inmsg, "msg", "m", "", "message to tokenize")
	scanCmd.Run = scan

	analyzeCmd.Flags().StringVarP(&infile, "infile", "i", "", "input file, required")
	analyzeCmd.Flags().StringVarP(&patfile, "patfile", "p", "", "initial pattern file, optional")
	analyzeCmd.Flags().StringVarP(&outfile, "outfile", "o", "", "output file, if empty, to stdout")
	analyzeCmd.Flags().StringVarP(&cpuprofile, "cpuprofile", "c", "", "CPU profile filename")
	analyzeCmd.Run = analyze

	parseCmd.Flags().StringVarP(&infile, "infile", "i", "", "input file, required ")
	parseCmd.Flags().StringVarP(&patfile, "patfile", "p", "", "initial pattern file, required")
	parseCmd.Flags().StringVarP(&outfile, "outfile", "o", "", "output file, if empty, to stdout")
	parseCmd.Flags().StringVarP(&cpuprofile, "cpuprofile", "c", "", "CPU profile filename")
	parseCmd.Run = parse

	benchCmd.Flags().StringVarP(&infile, "infile", "i", "", "input file, required ")
	benchCmd.Flags().StringVarP(&patfile, "patfile", "p", "", "initial pattern file, required")
	benchCmd.Flags().StringVarP(&cpuprofile, "cpuprofile", "c", "", "CPU profile filename")
	benchCmd.Flags().IntVarP(&workers, "workers", "w", 1, "number of parsing workers")
	benchCmd.Run = bench

	sequenceCmd.AddCommand(scanCmd)
	sequenceCmd.AddCommand(analyzeCmd)
	sequenceCmd.AddCommand(parseCmd)
	sequenceCmd.AddCommand(benchCmd)
}

func profile() {
	var f *os.File
	var err error

	if cpuprofile != "" {
		f, err = os.Create(cpuprofile)
		if err != nil {
			log.Fatal(err)
		}

		pprof.StartCPUProfile(f)
	}

	sigchan := make(chan os.Signal, 1)
	signal.Notify(sigchan, os.Interrupt, os.Kill)
	go func() {
		select {
		case sig := <-sigchan:
			log.Printf("Existing due to trapped signal; %v", sig)

		case <-quit:
			log.Println("Quiting...")

		}

		if f != nil {
			glog.Errorf("Stopping profile")
			pprof.StopCPUProfile()
			f.Close()
		}

		close(done)
		os.Exit(0)
	}()
}

func scan(cmd *cobra.Command, args []string) {
	s := sequence.NewScanner()
	seq, err := s.Scan(inmsg)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(seq.LongString())
}

func analyze(cmd *cobra.Command, args []string) {
	if infile == "" {
		log.Fatal("Invalid input file")
	}

	profile()

	parser := buildParser(patfile)
	analyzer := sequence.NewAnalyzer()

	// Open input file
	iscan, ifile := openFile(infile)
	defer ifile.Close()

	s := sequence.NewScanner()

	// For all the log messages, if we can't parse it, then let's add it to the
	// analyzer for pattern analysis
	for iscan.Scan() {
		line := iscan.Text()
		if len(line) == 0 || line[0] == '#' {
			continue
		}

		seq, err := s.Scan(line)
		if err != nil {
			log.Fatal(err)
		}

		if _, err = parser.Parse(seq); err != nil {
			analyzer.Add(seq)
		}
	}

	ifile.Close()
	analyzer.Finalize()

	iscan, ifile = openFile(infile)
	defer ifile.Close()

	pmap := make(map[string]map[string]string)
	amap := make(map[string]map[string]string)
	n := 0

	// Now that we have built the analyzer, let's go through each log message again
	// to determine the unique patterns
	for iscan.Scan() {
		line := iscan.Text()
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		n++

		seq, err := s.Scan(line)
		if err != nil {
			log.Fatal(err)
		}

		pseq, err := parser.Parse(seq)
		if err == nil {
			pat := pseq.String()
			sig := pseq.Signature()
			if _, ok := pmap[pat]; !ok {
				pmap[pat] = make(map[string]string)
			}
			pmap[pat][sig] = line
		} else {
			aseq, err := analyzer.Analyze(seq)
			if err != nil {
				log.Printf("Error parsing: %s", line)
			} else {
				pat := aseq.String()
				sig := aseq.Signature()
				if _, ok := amap[pat]; !ok {
					amap[pat] = make(map[string]string)
				}
				amap[pat][sig] = line
			}
		}
	}

	ofile := openOutputFile(outfile)
	defer ofile.Close()

	for pat, lines := range pmap {
		fmt.Fprintf(ofile, "%s\n", pat)
		for _, line := range lines {
			fmt.Fprintf(ofile, "# %s\n", line)
		}
		fmt.Fprintln(ofile)
	}

	for pat, lines := range amap {
		fmt.Fprintf(ofile, "%s\n", pat)
		for _, line := range lines {
			fmt.Fprintf(ofile, "# %s\n", line)
		}
		fmt.Fprintln(ofile)
	}

	log.Printf("Analyzed %d messages, found %d unique patterns, %d are new.", n, len(pmap)+len(amap), len(amap))
}

func parse(cmd *cobra.Command, args []string) {
	if patfile == "" {
		log.Fatal("Invalid pattern file")
	}

	if infile == "" {
		log.Fatal("Invalid input file")
	}

	profile()

	parser := buildParser(patfile)

	iscan, ifile := openFile(infile)
	defer ifile.Close()

	ofile := openOutputFile(outfile)
	defer ofile.Close()

	s := sequence.NewScanner()
	n := 0
	now := time.Now()

	for iscan.Scan() {
		line := iscan.Text()
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		n++

		seq, err := s.Scan(line)
		if err != nil {
			log.Fatal(err)
		}

		//pseq, err := parser.Parse(seq)
		_, err = parser.Parse(seq)
		if err != nil {
			log.Printf("Error parsing: %s", line)
		} else {
			//fmt.Fprintf(ofile, "%s\n%s\n\n", line, pseq.LongString())
		}
	}

	since := time.Since(now)
	log.Printf("Parsed %d messages in %.2f secs, ~ %.2f msgs/sec", n, float64(since)/float64(time.Second), float64(n)/(float64(since)/float64(time.Second)))
	close(quit)
	<-done
}

func bench(cmd *cobra.Command, args []string) {
	if patfile == "" {
		log.Fatal("Invalid pattern file")
	}

	if infile == "" {
		log.Fatal("Invalid input file")
	}

	profile()

	parser := buildParser(patfile)

	iscan, ifile := openFile(infile)
	defer ifile.Close()

	var lines []string
	n := 0

	for iscan.Scan() {
		line := iscan.Text()
		if len(line) == 0 || line[0] == '#' {
			continue
		}

		n++
		lines = append(lines, line)
	}

	s := sequence.NewScanner()
	now := time.Now()
	msgpipe := make(chan string, 1000)
	done2 := make(chan struct{})
	total := int64(0)

	for i := 0; i < workers; i++ {
		go func() {
			for line := range msgpipe {
				seq, err := s.Scan(line)
				if err != nil {
					log.Fatal(err)
				}

				_, err = parser.Parse(seq)
				if err != nil {
					log.Printf("Error parsing: %s", line)
				}

				t2 := atomic.AddInt64(&total, 1)
				if t2 == int64(n) {
					close(done2)
				}
			}
		}()
	}

	for _, line := range lines {
		msgpipe <- line
	}

	select {
	case <-done2:
		close(msgpipe)

	case <-time.Tick(30 * time.Second):
		log.Fatal("Timeout waiting for parsing to complete")
	}

	since := time.Since(now)
	log.Printf("Parsed %d messages in %.2f secs, ~ %.2f msgs/sec", n, float64(since)/float64(time.Second), float64(n)/(float64(since)/float64(time.Second)))
	close(quit)
	<-done
}

func buildParser(patfile string) *sequence.Parser {
	parser := sequence.NewParser()

	if patfile != "" {
		// Open pattern file
		pscan, pfile := openFile(patfile)
		defer pfile.Close()

		s := sequence.NewScanner()

		for pscan.Scan() {
			line := pscan.Text()
			if len(line) == 0 || line[0] == '#' {
				continue
			}

			seq, err := s.Scan(line)
			if err != nil {
				log.Fatal(err)
			}

			err = parser.Add(seq)
			if err != nil {
				log.Fatal(err)
			}
		}
	}

	return parser
}

func openFile(fname string) (*bufio.Scanner, *os.File) {
	var s *bufio.Scanner

	f, err := os.Open(fname)
	if err != nil {
		log.Fatal(err)
	}

	if strings.HasSuffix(fname, ".gz") {
		gunzip, err := gzip.NewReader(f)
		if err != nil {
			log.Fatal(err)
		}

		s = bufio.NewScanner(gunzip)
	} else {
		s = bufio.NewScanner(f)
	}

	return s, f
}

func openOutputFile(fname string) *os.File {
	var (
		ofile *os.File
		err   error
	)

	if fname == "" {
		ofile = os.Stdin
	} else {
		// Open output file
		ofile, err = os.OpenFile(fname, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
		if err != nil {
			log.Fatal(err)
		}
	}

	return ofile
}

func main() {
	sequenceCmd.Execute()
}
