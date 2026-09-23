package httpapi

import (
	"errors"
	"regexp"
	"strings"
)

// Resolvers own database access and missing-value diagnostics. These helpers do
// not query models, execute scripts, or write logs containing resolved secrets.
type ScriptValueResolver func(expression string) (any, error)
type ScriptSnippetResolver func(name string) (code string, found bool, err error)

var ErrUnsupportedScriptExpansion = errors.New("unsupported script expansion construct")

var scriptSnippetPattern = regexp.MustCompile(`{{(.*)}}`)
var scriptArgumentPattern = regexp.MustCompile(`^.*\{\{(.*)\}\}.*`)
var scriptReplacementPattern = regexp.MustCompile(`\{\{.*\}\}`)
var scriptCountedPattern = regexp.MustCompile(`\{[0-9,]`)

func expandScriptSnippets(code string, resolve ScriptSnippetResolver) (string, error) {
	// The match list is captured before substitution, matching Python finditer.
	matches := scriptSnippetPattern.FindAllStringSubmatch(code, -1)
	result := code
	for _, match := range matches {
		value, found, err := resolve(strings.TrimSpace(match[1]))
		if err != nil {
			return "", err
		}
		if !found {
			continue
		}
		// Python re.sub treats the full marker as a regex, not a literal.
		// Keep only the shared ASCII-regex subset; reject differing engines'
		// escapes, flags/lookaround, counted repeats and non-ASCII char classes.
		if strings.Contains(match[1], `\`) || scriptCountedPattern.MatchString(match[1]) || strings.Contains(match[1], "(?") || strings.Contains(match[1], "[:") || (strings.Contains(match[1], "[") && !asciiScriptText(match[1])) {
			return "", ErrUnsupportedScriptExpansion
		}
		pattern, err := regexp.Compile(match[0])
		if err != nil || pattern.MatchString("") {
			return "", ErrUnsupportedScriptExpansion
		}
		result = pattern.ReplaceAllStringFunc(result, func(string) string { return value })
	}
	return result, nil
}

func asciiScriptText(text string) bool {
	for _, r := range text {
		if r > 127 {
			return false
		}
	}
	return true
}

func expandScriptArgs(args []string, shell string, resolve ScriptValueResolver) ([]string, error) {
	result := make([]string, 0, len(args))
	for _, arg := range args {
		value, matched, err := scriptArgumentValue(arg, shell, shell != "cmd", resolve)
		if err != nil {
			return nil, err
		}
		if matched && value != "" {
			arg, err = substituteScriptValue(arg, value)
			if err != nil {
				return nil, err
			}
		}
		result = append(result, arg)
	}
	return result, nil
}

func expandScriptEnv(env []string, shell string, resolve ScriptValueResolver) ([]string, error) {
	result := make([]string, 0, len(env))
	for _, entry := range env {
		parts := strings.Split(entry, "=")
		if len(parts) < 2 {
			continue
		}
		value, matched, err := scriptArgumentValue(parts[1], shell, false, resolve)
		if err != nil {
			return nil, err
		}
		if !matched {
			result = append(result, entry)
		} else if value != "" {
			expanded, err := substituteScriptValue(parts[1], value)
			if err != nil {
				return nil, err
			}
			result = append(result, parts[0]+"="+expanded)
		}
	}
	return result, nil
}

func scriptArgumentValue(text, shell string, quotes bool, resolve ScriptValueResolver) (string, bool, error) {
	match := scriptArgumentPattern.FindStringSubmatch(text)
	if match == nil {
		return "", false, nil
	}
	value, err := resolve(match[1])
	if err != nil {
		return "", true, err
	}
	formatted, err := formatScriptValue(value, shell, quotes)
	return formatted, true, err
}

func substituteScriptValue(text, value string) (string, error) {
	// Python validates replacement syntax even when the pattern matches no
	// groups. On re.error the source retries with re.escape(value).
	if _, ok, err := scriptReplacement(value, ""); err != nil {
		return "", err
	} else if !ok {
		value = escapeScriptRegex(value)
	}
	return scriptReplacementPattern.ReplaceAllStringFunc(text, func(match string) string {
		result, _, _ := scriptReplacement(value, match)
		return result
	}), nil
}

func escapeScriptRegex(text string) string {
	var result strings.Builder
	for _, r := range text {
		if strings.ContainsRune("()[]{}?*+-|^$\\.&~# \t\n\r\v\f", r) {
			result.WriteByte('\\')
		}
		result.WriteRune(r)
	}
	return result.String()
}

// Replacement patterns have no capture groups; only group zero is valid.
func scriptReplacement(value, match string) (string, bool, error) {
	var result strings.Builder
	for i := 0; i < len(value); i++ {
		if value[i] != '\\' {
			result.WriteByte(value[i])
			continue
		}
		i++
		if i == len(value) {
			return "", false, nil
		}
		ch := value[i]
		if ch == 'g' {
			end := strings.IndexByte(value[i:], '>')
			if end >= 3 && value[i+1] == '<' {
				name := value[i+2 : i+end]
				if name[0] == '_' || name[0] >= 'a' && name[0] <= 'z' || name[0] >= 'A' && name[0] <= 'Z' || name[0] >= 128 {
					// Python raises IndexError, outside the source's re.error
					// fallback. Do not quietly turn it into a literal argument.
					return "", false, ErrUnsupportedScriptExpansion
				}
			}
			if end < 3 || value[i+1] != '<' || strings.Trim(value[i+2:i+end], "0") != "" {
				return "", false, nil
			}
			i += end
			result.WriteString(match)
			continue
		}
		if ch >= '0' && ch <= '9' {
			end := i
			for end < len(value) && end < i+3 && value[end] >= '0' && value[end] <= '7' {
				end++
			}
			if ch != '0' && end-i != 3 {
				return "", false, nil
			}
			n := 0
			for _, digit := range value[i:end] {
				n = n*8 + int(digit-'0')
			}
			if end == i || n > 255 {
				return "", false, nil
			}
			result.WriteRune(rune(n))
			i = end - 1
			continue
		}
		escapes := map[byte]byte{'a': '\a', 'b': '\b', 'f': '\f', 'n': '\n', 'r': '\r', 't': '\t', 'v': '\v', '\\': '\\'}
		if escaped, ok := escapes[ch]; ok {
			result.WriteByte(escaped)
			continue
		}
		if ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' {
			return "", false, nil
		}
		result.WriteByte('\\')
		result.WriteByte(ch)
	}
	return result.String(), true, nil
}
