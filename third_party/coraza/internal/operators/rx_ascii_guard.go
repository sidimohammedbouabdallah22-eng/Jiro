// Copyright 2026 OpenWAF contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"regexp/syntax"
	"unicode"
)

// asciiCondition is a necessary condition on the characters present in an
// ASCII match. It never reasons about adjacency, order, length or anchors.
// nil means unknown/true. Unicode input always falls back to the original RX.
type asciiCondition struct {
	mask     [2]uint64
	all      bool
	children []*asciiCondition
}

func (c *asciiCondition) possible(seen [2]uint64) bool {
	if c == nil {
		return true
	}
	if len(c.children) == 0 {
		return c.mask[0]&seen[0] != 0 || c.mask[1]&seen[1] != 0
	}
	for _, child := range c.children {
		value := child.possible(seen)
		if c.all && !value {
			return false
		}
		if !c.all && value {
			return true
		}
	}
	return c.all
}

func asciiCombine(all bool, children []*asciiCondition) *asciiCondition {
	kept := children[:0]
	for _, child := range children {
		if child == nil {
			if !all {
				return nil
			}
			continue
		}
		kept = append(kept, child)
	}
	if len(kept) == 0 {
		if all {
			return nil
		}
		return &asciiCondition{}
	}
	if len(kept) == 1 {
		return kept[0]
	}
	return &asciiCondition{all: all, children: kept}
}

func asciiSyntaxCondition(re *syntax.Regexp, depth int, budget *int) (*asciiCondition, bool) {
	*budget--
	if depth > 64 || *budget < 0 {
		return nil, false
	}
	switch re.Op {
	case syntax.OpNoMatch:
		return &asciiCondition{}, true
	case syntax.OpLiteral:
		parts := make([]*asciiCondition, 0, len(re.Rune))
		for _, character := range re.Rune {
			*budget--
			if *budget < 0 {
				return nil, false
			}
			part := &asciiCondition{}
			add := func(r rune) {
				if r >= 0 && r < 128 {
					part.mask[r>>6] |= uint64(1) << uint(r&63)
				}
			}
			add(character)
			if re.Flags&syntax.FoldCase != 0 {
				for r := unicode.SimpleFold(character); r != character; r = unicode.SimpleFold(r) {
					add(r)
				}
			}
			parts = append(parts, part)
		}
		return asciiCombine(true, parts), true
	case syntax.OpCharClass:
		part := &asciiCondition{}
		for i := 0; i < len(re.Rune); i += 2 {
			for r := max(0, re.Rune[i]); r <= min(127, re.Rune[i+1]); r++ {
				part.mask[r>>6] |= uint64(1) << uint(r&63)
			}
		}
		if part.mask[0] == ^uint64(0) && part.mask[1] == ^uint64(0) {
			return nil, true
		}
		return part, true
	case syntax.OpCapture, syntax.OpPlus:
		return asciiSyntaxCondition(re.Sub[0], depth+1, budget)
	case syntax.OpRepeat:
		if re.Min > 0 {
			return asciiSyntaxCondition(re.Sub[0], depth+1, budget)
		}
		return nil, true
	case syntax.OpConcat, syntax.OpAlternate:
		parts := make([]*asciiCondition, 0, len(re.Sub))
		for _, child := range re.Sub {
			part, ok := asciiSyntaxCondition(child, depth+1, budget)
			if !ok {
				return nil, false
			}
			parts = append(parts, part)
		}
		return asciiCombine(re.Op == syntax.OpConcat, parts), true
	default:
		// Optional repetitions, empty matches, boundaries and unsupported nodes
		// impose no necessary character requirement.
		return nil, true
	}
}

func conservativeASCIIReject(pattern string) func(string) bool {
	if disableASCIIReject {
		return nil
	}
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return nil
	}
	budget := 4096
	condition, ok := asciiSyntaxCondition(re, 0, &budget)
	if !ok || condition == nil {
		return nil
	}
	return func(value string) bool {
		// Avoid adding a scan to ordinary short inputs.
		if len(value) < 4096 {
			return true
		}
		var seen [2]uint64
		nextCheck := 4095
		for i := 0; i < len(value); i++ {
			character := value[i]
			if character >= 128 {
				return true
			}
			seen[character>>6] |= uint64(1) << uint(character&63)
			// Presence conditions are monotone: once possible, more input
			// cannot make them impossible. Bound checks geometrically so
			// diverse values fall back quickly without penalizing long runs.
			if i == nextCheck {
				if condition.possible(seen) {
					return true
				}
				nextCheck = (nextCheck+1)*4 - 1
			}
		}
		return condition.possible(seen)
	}
}
