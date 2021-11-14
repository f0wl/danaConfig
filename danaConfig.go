// ┌──────────────────────────────────┐
// │ Marius 'f0wL' Genheimer, 2021    │
// └──────────────────────────────────┘

package main

import (
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/fatih/color"
)

// check errors as they occur and panic :o
func check(e error) {
	if e != nil {
		panic(e)
	}
}

// calcSHA256 reads the sample file and calculates its SHA-256 hashsum
func calcSHA256(file string) string {
	f, readErr := os.Open(file)
	check(readErr)
	defer f.Close()

	h := sha256.New()
	_, hashErr := io.Copy(h, f)
	check(hashErr)
	return hex.EncodeToString(h.Sum(nil))
}

// calcMD5 reads the sample file and calculates its SHA-256 hashsum
func calcMD5(file string) string {

	f, readErr := os.Open(file)
	check(readErr)
	defer f.Close()

	h := md5.New()
	_, hashErr := io.Copy(h, f)
	check(hashErr)
	return hex.EncodeToString(h.Sum(nil))
}

// getFileInfo returns the size on disk of the specified file
func getFileInfo(file string) int64 {
	f, readErr := os.Open(file)
	check(readErr)
	defer f.Close()

	fileInfo, fileErr := f.Stat()
	check(fileErr)

	return fileInfo.Size()
}

// scanFile searches a byte array for a hex string; if found it returns the
// postition of the pattern. If it found nothing it will return -1
func scanFile(data []byte, search string) int {
	offBytes, byteErr := hex.DecodeString(search)
	check(byteErr)
	return bytes.Index(data, offBytes)
}

// hexToDottedIP rewrites the Command&Control-Server addresses from hexadecimal to dotted-decimal notation
func hexToDottedIP(hexbytes []byte) string {
	// super duper hacky conversion, but if it works, it ain't stupid
	str := hex.EncodeToString(hexbytes)
	okt1, parseErr := strconv.ParseInt(str[0:2], 16, 64)
	check(parseErr)
	okt2, parseErr := strconv.ParseInt(str[2:4], 16, 64)
	check(parseErr)
	okt3, parseErr := strconv.ParseInt(str[4:6], 16, 64)
	check(parseErr)
	okt4, parseErr := strconv.ParseInt(str[6:8], 16, 64)
	check(parseErr)
	ip := strconv.Itoa(int(okt1)) + "." + strconv.Itoa(int(okt2)) + "." + strconv.Itoa(int(okt3)) + "." + strconv.Itoa(int(okt4))
	return ip
}

// Structure to store extracted config information
type danaBotConfig struct {
	AffiliateID  int       `json:"affID"`
	EmbeddedHash string    `json:"embeddedHash"`
	Version      int       `json:"version"`
	Timeout      int       `json:"timeout"`
	C2Hosts      [4]string `json:"c2Hosts"`
	C2Ports      [4]int    `json:"c2Ports"`
	TorURL       string    `json:"torURL,omitempty"`
}

// Flag variables for commandline arguments
var jsonFlag bool

func main() {

	fmt.Printf("\n    ,--.                         ,-----.                ,---.,--.           ")
	fmt.Printf("\n  ,-|  | ,--,--.,--,--,  ,--,--.'  .--./ ,---. ,--,--, /  .-'`--' ,---.   ")
	fmt.Printf("\n ' .-. |' ,-.  ||      \\' ,-.  ||  |    | .-. ||      \\|  `-,,--.| .-. | ")
	fmt.Printf("\n \\ `-' |\\ '-'  ||  ||  |\\ '-'  |'  '--'\\' '-' '|  ||  ||  .-'|  |' '-' ' ")
	fmt.Printf("\n  `---'  `--`--'`--''--' `--`--' `-----' `---' `--''--'`--'  `--'.`-  /   ")
	fmt.Printf("\n                                                                 `---'      ")
	fmt.Printf("\n DanaBot Main Component Configuration Extractor")
	fmt.Printf("\n Marius 'f0wL' Genheimer | https://dissectingmalwa.re\n\n")

	// parse passed flags
	flag.BoolVar(&jsonFlag, "j", false, "Write extracted config to a JSON file")
	flag.Parse()

	if flag.NArg() == 0 {
		color.Red("✗ No path to sample provided.\n\n")
		os.Exit(1)
	}

	// calculate hash sums of the sample
	md5sum := calcMD5(flag.Args()[0])
	sha256sum := calcSHA256(flag.Args()[0])

	w1 := tabwriter.NewWriter(os.Stdout, 1, 1, 1, ' ', 0)
	fmt.Fprintln(w1, " → File size (bytes): \t", getFileInfo(flag.Args()[0]))
	fmt.Fprintln(w1, " → Sample MD5: \t", md5sum)
	fmt.Fprintln(w1, " → Sample SHA-256: \t", sha256sum)
	w1.Flush()
	print("\n")

	// read the contents of the file
	dllFile, readErr := ioutil.ReadFile(flag.Args()[0])
	check(readErr)

	offset := scanFile(dllFile, "4D0069006E00690049006E00690074003A004500780063006500700074000000") //  = MiniInit:Except (wide string)

	if offset == -1 {
		color.Red("\n ✗ Unable to find config offset.\n\n")
		os.Exit(1)
	}

	// correct offset for pattern bytes
	offset = offset + 32

	// init the config struct
	var cfg danaBotConfig

	offset += 60
	cfg.AffiliateID = int(binary.LittleEndian.Uint32((dllFile[offset : offset+4])))
	offset += 4

	offset += 54
	cfg.Version = int(binary.LittleEndian.Uint32(dllFile[offset : offset+4]))
	offset += 4

	offset += 50
	cfg.Timeout = int(binary.LittleEndian.Uint32(dllFile[offset : offset+4]))
	offset += 4

	// parse the four C2 host IPs...
	for i := 0; i < 4; i++ {
		offset += 6
		cfg.C2Hosts[i] = hexToDottedIP(dllFile[offset : offset+4])
		offset += 4
	}

	// ...and the ports for the C2 communication
	for i := 0; i < 4; i++ {
		offset += 6
		cfg.C2Ports[i] = int(binary.LittleEndian.Uint32(dllFile[offset : offset+4]))
		offset += 4
	}

	offset += 4
	cfg.EmbeddedHash = string(dllFile[offset : offset+32])

	// search for the onion address
	torOffset := scanFile(dllFile, "2E6F6E696F6E") //  = .onion

	if torOffset == -1 {
		color.Red("\n ✗ Unable to find Tor URL offset.\n\n")
		os.Exit(1)
	} else {
		torOffset -= 56 // correct for the legth of a v3 Tor URL
		cfg.TorURL = string(dllFile[torOffset : torOffset+62])
	}

	fmt.Fprintln(w1, " Affiliate ID: \t", cfg.AffiliateID)
	fmt.Fprintln(w1, " Embedded Hash: \t", cfg.EmbeddedHash)
	fmt.Fprintln(w1, " Version: \t", cfg.Version)
	fmt.Fprintln(w1, " Timeout: \t", cfg.Timeout)
	w1.Flush()

	fmt.Printf("\n C2 #1 → %v:%v\n", cfg.C2Hosts[0], cfg.C2Ports[0])
	fmt.Printf(" C2 #2 → %v:%v\n", cfg.C2Hosts[1], cfg.C2Ports[1])
	fmt.Printf(" C2 #3 → %v:%v\n", cfg.C2Hosts[2], cfg.C2Ports[2])
	fmt.Printf(" C2 #4 → %v:%v\n", cfg.C2Hosts[3], cfg.C2Ports[3])

	if cfg.TorURL != "" {
		fmt.Printf("\n Tor URL: %v\n\n", cfg.TorURL)
	}

	// if the program is run with -j the configuration will be written to disk in a JSON file
	if jsonFlag {

		// marshalling the config struct into a JSON string
		data, _ := json.Marshal(cfg)
		jsonString := string(data)
		// strip the unicode garbage
		jsonString = strings.ReplaceAll(jsonString, `\u0000`, "")

		// concat the filename for the json file output
		filename := "config-" + md5sum + ".json"

		// write the JSON string to a file
		jsonOutput, writeErr := os.Create(filename)
		check(writeErr)
		defer jsonOutput.Close()
		n3, err := jsonOutput.WriteString(jsonString)
		check(err)
		color.Green(" ✓ Wrote %d bytes to %v\n\n", n3, filename)
		jsonOutput.Sync()

	}

}
