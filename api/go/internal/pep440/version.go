package pep440

import (
	"errors"
	"regexp"
	"strings"
)

// PEP 440 syntax shared by normalization and ordering.
var versionPattern = regexp.MustCompile(`(?i)^v?(?:([0-9]+)!)?([0-9]+(?:\.[0-9]+)*)(?:[-_.]?(alpha|a|beta|b|preview|pre|c|rc)[-_.]?([0-9]+)?)?(?:(?:-([0-9]+))|(?:[-_.]?(post|rev|r)[-_.]?([0-9]+)?))?(?:[-_.]?(dev)[-_.]?([0-9]+)?)?(?:\+([a-z0-9]+(?:[-_.][a-z0-9]+)*))?$`)
var localSeparator = regexp.MustCompile(`[-_.]`)

func decimal(value string) string {
	value = strings.TrimLeft(value, "0")
	if value == "" {
		return "0"
	}
	return value
}

func Canonical(raw string) (string, error) {
	parts := versionPattern.FindStringSubmatch(strings.TrimSpace(raw))
	if parts == nil {
		return "", errors.New("invalid PEP 440 version")
	}
	release := strings.Split(parts[2], ".")
	for i := range release {
		release[i] = decimal(release[i])
	}
	for len(release) > 1 && release[len(release)-1] == "0" {
		release = release[:len(release)-1]
	}
	value := decimal(parts[1]) + "!" + strings.Join(release, ".")
	if parts[3] != "" {
		label := strings.ToLower(parts[3])
		switch label {
		case "alpha":
			label = "a"
		case "beta":
			label = "b"
		case "preview", "pre", "c":
			label = "rc"
		}
		value += label + decimal(parts[4])
	}
	if parts[5] != "" {
		value += ".post" + decimal(parts[5])
	} else if parts[6] != "" {
		value += ".post" + decimal(parts[7])
	}
	if parts[8] != "" {
		value += ".dev" + decimal(parts[9])
	}
	if parts[10] != "" {
		local := localSeparator.Split(strings.ToLower(parts[10]), -1)
		for i, part := range local {
			numeric := true
			for _, r := range part {
				if r < '0' || r > '9' {
					numeric = false
					break
				}
			}
			if numeric {
				local[i] = decimal(part)
			}
		}
		value += "+" + strings.Join(local, ".")
	}
	return value, nil
}
