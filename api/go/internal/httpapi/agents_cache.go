package httpapi

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/redis/go-redis/v9"
)

// Django's Redis cache stores dict values as pickles under ":<version>:<key>".
// agentChecksCache reads the per-agent check summary that Django's
// AgentTableSerializer.get_checks returns, without executing arbitrary pickles.
const agentChecksKeyPrefix = ":1:agent_checks_data_"

var zeroChecks = map[string]any{
	"total": int64(0), "passing": int64(0), "failing": int64(0),
	"warning": int64(0), "info": int64(0), "has_failing_checks": false,
}

func (s *Server) agentChecks(ctx context.Context, ids []int64) (map[int64]map[string]any, error) {
	out := make(map[int64]map[string]any, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	if s.Cache == nil {
		return nil, errors.New("agent check cache is not configured")
	}
	keys := make([]string, len(ids))
	for i, id := range ids {
		keys[i] = fmt.Sprintf("%s%d", agentChecksKeyPrefix, id)
	}
	values, err := s.Cache.MGet(ctx, keys...).Result()
	if err != nil && !errors.Is(err, redis.Nil) {
		return nil, err
	}
	for i, id := range ids {
		raw, _ := values[i].(string)
		if values[i] == nil {
			out[id] = zeroChecks // Django's cache-miss default
			continue
		}
		parsed, err := unpickleFlatDict([]byte(raw))
		if err != nil {
			return nil, err
		}
		out[id] = parsed
	}
	return out, nil
}

// unpickleFlatDict decodes protocol 2-5 pickles of a dict with string keys and
// int/bool values, the only shape calculate_agent_checks produces. Any other
// opcode is rejected.
func unpickleFlatDict(b []byte) (map[string]any, error) {
	var stack []any
	var marks []int
	memo := map[uint32]any{}
	var memoN uint32
	bad := errors.New("unsupported cached agent checks value")
	need := func(i, n int) bool { return n >= 0 && i+n <= len(b) }
	for i := 0; i < len(b); {
		op := b[i]
		i++
		switch op {
		case 0x80: // PROTO
			i++
		case 0x95: // FRAME
			i += 8
		case '}':
			stack = append(stack, map[string]any{})
		case 0x94: // MEMOIZE
			if len(stack) == 0 {
				return nil, bad
			}
			memo[memoN] = stack[len(stack)-1]
			memoN++
		case '(':
			marks = append(marks, len(stack))
		case 0x8c, 'X': // SHORT_BINUNICODE, BINUNICODE
			size := 0
			if op == 0x8c {
				if !need(i, 1) {
					return nil, bad
				}
				size = int(b[i])
				i++
			} else {
				if !need(i, 4) {
					return nil, bad
				}
				size = int(binary.LittleEndian.Uint32(b[i:]))
				i += 4
			}
			if !need(i, size) {
				return nil, bad
			}
			stack = append(stack, string(b[i:i+size]))
			i += size
		case 'K':
			if !need(i, 1) {
				return nil, bad
			}
			stack = append(stack, int64(b[i]))
			i++
		case 'M':
			if !need(i, 2) {
				return nil, bad
			}
			stack = append(stack, int64(binary.LittleEndian.Uint16(b[i:])))
			i += 2
		case 'J':
			if !need(i, 4) {
				return nil, bad
			}
			stack = append(stack, int64(int32(binary.LittleEndian.Uint32(b[i:]))))
			i += 4
		case 0x88:
			stack = append(stack, true)
		case 0x89:
			stack = append(stack, false)
		case 'h', 'j':
			var n uint32
			if op == 'h' {
				if !need(i, 1) {
					return nil, bad
				}
				n = uint32(b[i])
				i++
			} else {
				if !need(i, 4) {
					return nil, bad
				}
				n = binary.LittleEndian.Uint32(b[i:])
				i += 4
			}
			v, ok := memo[n]
			if !ok {
				return nil, bad
			}
			stack = append(stack, v)
		case 'u': // SETITEMS
			if len(marks) == 0 {
				return nil, bad
			}
			m := marks[len(marks)-1]
			marks = marks[:len(marks)-1]
			if m < 1 || (len(stack)-m)%2 != 0 {
				return nil, bad
			}
			dict, ok := stack[m-1].(map[string]any)
			if !ok {
				return nil, bad
			}
			for j := m; j < len(stack); j += 2 {
				key, ok := stack[j].(string)
				if !ok {
					return nil, bad
				}
				dict[key] = stack[j+1]
			}
			stack = stack[:m]
		case '.':
			if len(stack) != 1 {
				return nil, bad
			}
			dict, ok := stack[0].(map[string]any)
			if !ok {
				return nil, bad
			}
			return dict, nil
		default:
			return nil, bad
		}
	}
	return nil, bad
}
