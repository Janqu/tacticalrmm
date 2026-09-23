package jobs

import "github.com/amidaware/tacticalrmm/api/go/internal/pep440"

func canonicalVersion(raw string) (string, error) { return pep440.Canonical(raw) }
