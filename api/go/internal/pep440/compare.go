package pep440

import "strings"

// Version is a parsed PEP 440 comparison key. Decimal components remain strings
// so Python's arbitrary-size integers cannot overflow during comparisons.
type Version struct {
	epoch, preLabel, pre, post, dev string
	release, local                  []string
	hasPost, hasDev                 bool
}

func Parse(raw string) (Version, error) {
	canonical, err := Canonical(raw)
	if err != nil {
		return Version{}, err
	}
	p := versionPattern.FindStringSubmatch(canonical)
	v := Version{epoch: p[1], release: strings.Split(p[2], "."), preLabel: p[3], pre: decimal(p[4]),
		post: decimal(p[7]), dev: decimal(p[9]), hasPost: p[6] != "", hasDev: p[8] != ""}
	if p[10] != "" {
		v.local = strings.Split(p[10], ".")
	}
	return v, nil
}

func numberCompare(a, b string) int {
	if len(a) < len(b) {
		return -1
	}
	if len(a) > len(b) {
		return 1
	}
	return strings.Compare(a, b)
}

func preRank(v Version) int {
	if v.preLabel == "" {
		if v.hasDev && !v.hasPost {
			return -1
		}
		return 3
	}
	switch v.preLabel {
	case "a":
		return 0
	case "b":
		return 1
	default:
		return 2 // rc
	}
}

// Compare returns -1, 0 or 1, following packaging.version.Version ordering.
func Compare(a, b Version) int {
	if c := numberCompare(a.epoch, b.epoch); c != 0 {
		return c
	}
	for i := 0; i < len(a.release) || i < len(b.release); i++ {
		x, y := "0", "0"
		if i < len(a.release) {
			x = a.release[i]
		}
		if i < len(b.release) {
			y = b.release[i]
		}
		if c := numberCompare(x, y); c != 0 {
			return c
		}
	}
	ap, bp := preRank(a), preRank(b)
	if ap < bp {
		return -1
	}
	if ap > bp {
		return 1
	}
	if a.preLabel != "" {
		if c := numberCompare(a.pre, b.pre); c != 0 {
			return c
		}
	}
	if a.hasPost != b.hasPost {
		if a.hasPost {
			return 1
		}
		return -1
	}
	if a.hasPost {
		if c := numberCompare(a.post, b.post); c != 0 {
			return c
		}
	}
	if a.hasDev != b.hasDev {
		if a.hasDev {
			return -1
		}
		return 1
	}
	if a.hasDev {
		if c := numberCompare(a.dev, b.dev); c != 0 {
			return c
		}
	}
	for i := 0; i < len(a.local) && i < len(b.local); i++ {
		x, y := a.local[i], b.local[i]
		xn, yn := strings.Trim(x, "0123456789") == "", strings.Trim(y, "0123456789") == ""
		if xn != yn {
			if xn {
				return 1
			}
			return -1
		}
		c := strings.Compare(x, y)
		if xn {
			c = numberCompare(x, y)
		}
		if c != 0 {
			return c
		}
	}
	if len(a.local) < len(b.local) {
		return -1
	}
	if len(a.local) > len(b.local) {
		return 1
	}
	return 0
}
