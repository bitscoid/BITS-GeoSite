package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/sagernet/sing-box/common/geosite"
	"github.com/sagernet/sing-box/common/srs"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"

	"github.com/google/go-github/v45/github"
	"github.com/v2fly/v2ray-core/v5/app/router/routercommon"
	"google.golang.org/protobuf/proto"
)

type additionalList struct {
	name string
	url  string
}

var additionalLists = []additionalList{
	{"oisd-full", "https://big.oisd.nl/dnsmasq"},
	{"oisd-small", "https://small.oisd.nl/dnsmasq"},
	{"oisd-nsfw", "https://nsfw.oisd.nl/dnsmasq"},
	{"d3ward", "https://raw.githubusercontent.com/Turtlecute33/adblocktest/master/src/d3host.txt"},
	{"antiscam", "https://raw.githubusercontent.com/malikshi/antiscam/refs/heads/main/antiscam.txt"},
	{"rule-ads", "https://raw.githubusercontent.com/Turtlecute33/adblocktest/master/src/d3host.txt"},
	{"rule-ads", "https://raw.githubusercontent.com/malikshi/v2ray-rules-dat/rule/rule_ads.txt"},
	{"rule-doh", "https://raw.githubusercontent.com/malikshi/dns_ip/main/domains-doh.txt"},
	{"rule-gaming", "https://raw.githubusercontent.com/malikshi/v2ray-rules-dat/rule/rule_gaming.txt"},
	{"rule-indo", "https://raw.githubusercontent.com/malikshi/v2ray-rules-dat/rule/rule_indo.txt"},
	{"rule-playstore", "https://raw.githubusercontent.com/malikshi/v2ray-rules-dat/rule/rule_playstore.txt"},
	{"rule-sosmed", "https://raw.githubusercontent.com/malikshi/v2ray-rules-dat/rule/rule_sosmed.txt"},
	{"rule-streaming", "https://raw.githubusercontent.com/malikshi/v2ray-rules-dat/rule/rule_streaming.txt"},
	{"rule-umum", "https://raw.githubusercontent.com/malikshi/v2ray-rules-dat/rule/rule_umum.txt"},
	{"rule-ipcheck", "https://raw.githubusercontent.com/malikshi/v2ray-rules-dat/rule/rule_ipcheck.txt"},
	{"rule-speedtest", "https://raw.githubusercontent.com/malikshi/v2ray-rules-dat/rule/rule_speedtest.txt"},
	{"videoconference", "https://raw.githubusercontent.com/malikshi/v2ray-rules-dat/rule/rule-videoconference.txt"},
	{"rule-malicious", "https://raw.githubusercontent.com/elliotwutingfeng/Inversion-DNSBL-Blocklists/main/Google_hostnames_light.txt"},
	{"urltest", "https://raw.githubusercontent.com/malikshi/v2ray-rules-dat/rule/urltest.txt"},
}

var domainPattern = regexp.MustCompile(`(?i)^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)

var (
	githubClient *github.Client
	httpClient   = &http.Client{Timeout: 10 * time.Minute}
)

func init() {
	accessToken, loaded := os.LookupEnv("ACCESS_TOKEN")
	if !loaded {
		githubClient = github.NewClient(nil)
		return
	}
	transport := &github.BasicAuthTransport{
		Username: accessToken,
	}
	githubClient = github.NewClient(transport.Client())
}

func fetch(from string) (*github.RepositoryRelease, error) {
	fixedRelease := os.Getenv("FIXED_RELEASE")
	names := strings.SplitN(from, "/", 2)
	if len(names) != 2 || names[0] == "" || names[1] == "" {
		return nil, E.New("invalid GitHub repository: ", from)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	var latestRelease *github.RepositoryRelease
	var err error
	if fixedRelease != "" {
		latestRelease, _, err = githubClient.Repositories.GetReleaseByTag(ctx, names[0], names[1], fixedRelease)
	} else {
		latestRelease, _, err = githubClient.Repositories.GetLatestRelease(ctx, names[0], names[1])
	}
	if err != nil {
		return nil, err
	}
	return latestRelease, err
}

func get(downloadURL *string) ([]byte, error) {
	log.Info("download ", *downloadURL)
	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		response, err := httpClient.Get(*downloadURL)
		if err == nil && response.StatusCode == http.StatusOK {
			data, readErr := io.ReadAll(response.Body)
			response.Body.Close()
			if readErr == nil {
				return data, nil
			}
			lastErr = readErr
		} else {
			if err != nil {
				lastErr = err
			} else {
				lastErr = E.New("download failed with status ", response.Status)
				response.Body.Close()
			}
		}
		if attempt < 3 {
			time.Sleep(time.Duration(attempt) * time.Second)
		}
	}
	return nil, lastErr
}

func parseAdditionalDomains(data []byte) []string {
	seen := make(map[string]struct{})
	var domains []string
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(strings.SplitN(raw, "#", 2)[0])
		if line == "" || strings.HasPrefix(line, "!") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "server=/") {
			line = strings.TrimPrefix(line, "server=/")
			if end := strings.IndexByte(line, '/'); end >= 0 {
				line = line[:end]
			}
		} else if strings.HasPrefix(line, "||") {
			line = strings.TrimPrefix(line, "||")
			if end := strings.IndexAny(line, "^/\t "); end >= 0 {
				line = line[:end]
			}
		} else {
			fields := strings.Fields(line)
			if len(fields) > 1 && (fields[0] == "0.0.0.0" || fields[0] == "127.0.0.1") {
				line = fields[1]
			} else if len(fields) > 1 && strings.Contains(fields[0], ":") {
				line = fields[1]
			}
		}
		line = strings.TrimPrefix(line, "full:")
		line = strings.TrimPrefix(line, "domain:")
		line = strings.TrimSpace(strings.TrimSuffix(line, "."))
		if !domainPattern.MatchString(line) {
			continue
		}
		line = strings.ToLower(line)
		if _, ok := seen[line]; ok {
			continue
		}
		seen[line] = struct{}{}
		domains = append(domains, line)
	}
	sort.Strings(domains)
	return domains
}

func fetchAdditionalLists(domainMap map[string][]geosite.Item) error {
	for _, list := range additionalLists {
		data, err := get(&list.url)
		if err != nil {
			return E.Cause(err, "download additional list ", list.name)
		}
		for _, domain := range parseAdditionalDomains(data) {
			domainMap[list.name] = append(domainMap[list.name], geosite.Item{
				Type:  geosite.RuleTypeDomainSuffix,
				Value: "." + domain,
			})
		}
		if len(domainMap[list.name]) == 0 {
			return E.New("additional list is empty: ", list.name)
		}
		domainMap[list.name] = common.Uniq(domainMap[list.name])
	}
	return nil
}

func download(release *github.RepositoryRelease) ([]byte, error) {
	geositeAsset := common.Find(release.Assets, func(it *github.ReleaseAsset) bool {
		return *it.Name == "dlc.dat"
	})
	geositeChecksumAsset := common.Find(release.Assets, func(it *github.ReleaseAsset) bool {
		return *it.Name == "dlc.dat.sha256sum"
	})
	if geositeAsset == nil {
		return nil, E.New("geosite asset not found in upstream release ", release.Name)
	}
	if geositeChecksumAsset == nil {
		return nil, E.New("geosite asset not found in upstream release ", release.Name)
	}
	data, err := get(geositeAsset.BrowserDownloadURL)
	if err != nil {
		return nil, err
	}
	remoteChecksum, err := get(geositeChecksumAsset.BrowserDownloadURL)
	if err != nil {
		return nil, err
	}
	checksum := sha256.Sum256(data)
	remote := strings.Fields(string(remoteChecksum))
	if len(remote) == 0 || !strings.EqualFold(hex.EncodeToString(checksum[:]), remote[0]) {
		return nil, E.New("checksum mismatch")
	}
	return data, nil
}

func parse(vGeositeData []byte) (map[string][]geosite.Item, error) {
	vGeositeList := routercommon.GeoSiteList{}
	err := proto.Unmarshal(vGeositeData, &vGeositeList)
	if err != nil {
		return nil, err
	}
	domainMap := make(map[string][]geosite.Item)
	for _, vGeositeEntry := range vGeositeList.Entry {
		code := strings.ToLower(vGeositeEntry.CountryCode)
		domains := make([]geosite.Item, 0, len(vGeositeEntry.Domain)*2)
		attributes := make(map[string][]*routercommon.Domain)
		for _, domain := range vGeositeEntry.Domain {
			if len(domain.Attribute) > 0 {
				for _, attribute := range domain.Attribute {
					attributes[attribute.Key] = append(attributes[attribute.Key], domain)
				}
			}
			switch domain.Type {
			case routercommon.Domain_Plain:
				domains = append(domains, geosite.Item{
					Type:  geosite.RuleTypeDomainKeyword,
					Value: domain.Value,
				})
			case routercommon.Domain_Regex:
				domains = append(domains, geosite.Item{
					Type:  geosite.RuleTypeDomainRegex,
					Value: domain.Value,
				})
			case routercommon.Domain_RootDomain:
				if strings.Contains(domain.Value, ".") {
					domains = append(domains, geosite.Item{
						Type:  geosite.RuleTypeDomain,
						Value: domain.Value,
					})
				}
				domains = append(domains, geosite.Item{
					Type:  geosite.RuleTypeDomainSuffix,
					Value: "." + domain.Value,
				})
			case routercommon.Domain_Full:
				domains = append(domains, geosite.Item{
					Type:  geosite.RuleTypeDomain,
					Value: domain.Value,
				})
			}
		}
		domainMap[code] = common.Uniq(domains)
		for attribute, attributeEntries := range attributes {
			attributeDomains := make([]geosite.Item, 0, len(attributeEntries)*2)
			for _, domain := range attributeEntries {
				switch domain.Type {
				case routercommon.Domain_Plain:
					attributeDomains = append(attributeDomains, geosite.Item{
						Type:  geosite.RuleTypeDomainKeyword,
						Value: domain.Value,
					})
				case routercommon.Domain_Regex:
					attributeDomains = append(attributeDomains, geosite.Item{
						Type:  geosite.RuleTypeDomainRegex,
						Value: domain.Value,
					})
				case routercommon.Domain_RootDomain:
					if strings.Contains(domain.Value, ".") {
						attributeDomains = append(attributeDomains, geosite.Item{
							Type:  geosite.RuleTypeDomain,
							Value: domain.Value,
						})
					}
					attributeDomains = append(attributeDomains, geosite.Item{
						Type:  geosite.RuleTypeDomainSuffix,
						Value: "." + domain.Value,
					})
				case routercommon.Domain_Full:
					attributeDomains = append(attributeDomains, geosite.Item{
						Type:  geosite.RuleTypeDomain,
						Value: domain.Value,
					})
				}
			}
			domainMap[code+"@"+attribute] = common.Uniq(attributeDomains)
		}
	}
	return domainMap, nil
}

type filteredCodePair struct {
	code    string
	badCode string
}

func filterTags(data map[string][]geosite.Item) {
	var codeList []string
	for code := range data {
		codeList = append(codeList, code)
	}
	var badCodeList []filteredCodePair
	var filteredCodeMap []string
	var mergedCodeMap []string
	for _, code := range codeList {
		codeParts := strings.Split(code, "@")
		if len(codeParts) != 2 {
			continue
		}
		leftParts := strings.Split(codeParts[0], "-")
		var lastName string
		if len(leftParts) > 1 {
			lastName = leftParts[len(leftParts)-1]
		}
		if lastName == "" {
			lastName = codeParts[0]
		}
		if lastName == codeParts[1] {
			delete(data, code)
			filteredCodeMap = append(filteredCodeMap, code)
			continue
		}
		if "!"+lastName == codeParts[1] {
			badCodeList = append(badCodeList, filteredCodePair{
				code:    codeParts[0],
				badCode: code,
			})
		} else if lastName == "!"+codeParts[1] {
			badCodeList = append(badCodeList, filteredCodePair{
				code:    codeParts[0],
				badCode: code,
			})
		}
	}
	for _, it := range badCodeList {
		badList := data[it.badCode]
		if badList == nil {
			panic("bad list not found: " + it.badCode)
		}
		delete(data, it.badCode)
		newMap := make(map[geosite.Item]bool)
		for _, item := range data[it.code] {
			newMap[item] = true
		}
		for _, item := range badList {
			delete(newMap, item)
		}
		newList := make([]geosite.Item, 0, len(newMap))
		for item := range newMap {
			newList = append(newList, item)
		}
		data[it.code] = newList
		mergedCodeMap = append(mergedCodeMap, it.badCode)
	}
	sort.Strings(filteredCodeMap)
	sort.Strings(mergedCodeMap)
	os.Stderr.WriteString("filtered " + strings.Join(filteredCodeMap, ",") + "\n")
	os.Stderr.WriteString("merged " + strings.Join(mergedCodeMap, ",") + "\n")
}

func mergeTags(data map[string][]geosite.Item) {
	var codeList []string
	for code := range data {
		codeList = append(codeList, code)
	}
	var idCodeList []string
	for _, code := range codeList {
		codeParts := strings.Split(code, "@")
		if len(codeParts) != 2 {
			continue
		}
		if codeParts[1] != "id" {
			continue
		}
		if !strings.HasPrefix(codeParts[0], "category-") {
			continue
		}
		if strings.HasSuffix(codeParts[0], "-id") || strings.HasSuffix(codeParts[0], "-!id") {
			continue
		}
		idCodeList = append(idCodeList, code)
	}
	for _, code := range codeList {
		if !strings.HasPrefix(code, "category-") {
			continue
		}
		if !strings.HasSuffix(code, "-id") {
			continue
		}
		if strings.Contains(code, "@") {
			continue
		}
		idCodeList = append(idCodeList, code)
	}
	newMap := make(map[geosite.Item]bool)
	for _, item := range data["geolocation-id"] {
		newMap[item] = true
	}
	for _, code := range idCodeList {
		for _, item := range data[code] {
			newMap[item] = true
		}
	}
	newList := make([]geosite.Item, 0, len(newMap))
	for item := range newMap {
		newList = append(newList, item)
	}
	data["geolocation-id"] = newList
	data["id"] = append(newList, geosite.Item{
		Type:  geosite.RuleTypeDomainSuffix,
		Value: "id",
	})
	println("merged id categories: " + strings.Join(idCodeList, ","))
}

func generate(release *github.RepositoryRelease, output string, minOutput string, ruleSetOutput string, ruleSetUnstableOutput string) error {
	vData, err := download(release)
	if err != nil {
		return err
	}
	domainMap, err := parse(vData)
	if err != nil {
		return err
	}
	if err = fetchAdditionalLists(domainMap); err != nil {
		return err
	}
	filterTags(domainMap)
	mergeTags(domainMap)
	outputPath, _ := filepath.Abs(output)
	os.Stderr.WriteString("write " + outputPath + "\n")
	outputFile, err := os.Create(output)
	if err != nil {
		return err
	}
	defer outputFile.Close()
	writer := bufio.NewWriter(outputFile)
	err = geosite.Write(writer, domainMap)
	if err != nil {
		return err
	}
	err = writer.Flush()
	if err != nil {
		return err
	}
	// Minimal database: categories consumed by BITS Box default routes
	// (block ads via rule-ads, Indonesia bypass via rule-indo / id).
	// Keeps the bundled APK asset tiny while default rules keep working.
	minCodes := []string{
		"id",
		"rule-ads",
		"rule-indo",
	}
	minDomainMap := make(map[string][]geosite.Item)
	for _, minCode := range minCodes {
		domains, ok := domainMap[minCode]
		if !ok || len(domains) == 0 {
			return E.New("missing category for minimal database: ", minCode)
		}
		minDomainMap[minCode] = domains
	}
	minOutputFile, err := os.Create(minOutput)
	if err != nil {
		return err
	}
	defer minOutputFile.Close()
	writer.Reset(minOutputFile)
	err = geosite.Write(writer, minDomainMap)
	if err != nil {
		return err
	}
	err = writer.Flush()
	if err != nil {
		return err
	}
	os.RemoveAll(ruleSetOutput)
	os.RemoveAll(ruleSetUnstableOutput)
	if err = os.MkdirAll(ruleSetOutput, 0o755); err != nil {
		return err
	}
	if err = os.MkdirAll(ruleSetUnstableOutput, 0o755); err != nil {
		return err
	}
	for code, domains := range domainMap {
		var headlessRule option.DefaultHeadlessRule
		defaultRule := geosite.Compile(domains)
		headlessRule.Domain = defaultRule.Domain
		headlessRule.DomainSuffix = defaultRule.DomainSuffix
		headlessRule.DomainKeyword = defaultRule.DomainKeyword
		headlessRule.DomainRegex = defaultRule.DomainRegex
		var plainRuleSet option.PlainRuleSet
		plainRuleSet.Rules = []option.HeadlessRule{
			{
				Type:           C.RuleTypeDefault,
				DefaultOptions: headlessRule,
			},
		}
		srsPath, _ := filepath.Abs(filepath.Join(ruleSetOutput, "geosite-"+code+".srs"))
		unstableSRSPath, _ := filepath.Abs(filepath.Join(ruleSetUnstableOutput, "geosite-"+code+".srs"))
		// os.Stderr.WriteString("write " + srsPath + "\n")
		var (
			outputRuleSet         *os.File
			outputRuleSetUnstable *os.File
		)
		outputRuleSet, err = os.Create(srsPath)
		if err != nil {
			return err
		}
		err = srs.Write(outputRuleSet, plainRuleSet, C.RuleSetVersion1)
		outputRuleSet.Close()
		if err != nil {
			return err
		}
		outputRuleSetUnstable, err = os.Create(unstableSRSPath)
		if err != nil {
			return err
		}
		err = srs.Write(outputRuleSetUnstable, plainRuleSet, C.RuleSetVersion2)
		outputRuleSetUnstable.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func setActionOutput(name string, content string) {
	path := os.Getenv("GITHUB_OUTPUT")
	if path == "" {
		log.Warn("GITHUB_OUTPUT not set, skipping output: ", name)
		return
	}
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644)
	if err != nil {
		log.Warn("failed to open GITHUB_OUTPUT: ", err)
		return
	}
	defer file.Close()
	_, _ = fmt.Fprintf(file, "%s=%s\n", name, content)
}

func release(source string, destination string, output string, minOutput string, ruleSetOutput string, ruleSetOutputUnstable string) error {
	sourceRelease, err := fetch(source)
	if err != nil {
		return err
	}
	destinationRelease, err := fetch(destination)
	if err != nil {
		log.Warn("missing destination latest release")
	} else {
		if os.Getenv("NO_SKIP") != "true" && strings.Contains(*destinationRelease.Name, *sourceRelease.Name) {
			log.Info("already latest")
			setActionOutput("skip", "true")
			return nil
		}
	}
	err = generate(sourceRelease, output, minOutput, ruleSetOutput, ruleSetOutputUnstable)
	if err != nil {
		return err
	}
	setActionOutput("tag", *sourceRelease.Name)
	return nil
}

func main() {
	err := release(
		"v2fly/domain-list-community",
		"bitscoid/BITS-GeoSite",
		"geosite.db",
		"geosite-min.db",
		"rule-set",
		"rule-set-unstable",
	)
	if err != nil {
		log.Fatal(err)
	}
}
