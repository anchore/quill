package bundle

import (
	"fmt"
	"regexp"
	"strings"
)

// rule is a single resource rule used to decide how a file within a bundle is sealed
// into the CodeResources file. These mirror the rules embedded by Apple's codesign tool
// under the "rules" (version 1) and "rules2" (version 2) sections.
type rule struct {
	// pattern is the regular expression matched against the normalized (Contents/-stripped) relative path
	pattern *regexp.Regexp

	// exclude marks paths that are skipped entirely; exclusion rules are internal to the
	// signing process and are not written to the CodeResources file
	exclude bool

	// nested marks paths that contain signable code (e.g. Frameworks/, PlugIns/) which are
	// sealed by their code signature rather than a content hash
	nested bool

	// omit marks paths that may exist in the bundle but whose content is not sealed
	omit bool

	// optional marks paths that may be missing when the seal is verified
	optional bool

	// weight determines rule precedence (higher wins); the implicit default weight is 1
	weight uint32
}

func newRule(pattern string) rule {
	return rule{
		// note: all default rule patterns are known to compile
		pattern: regexp.MustCompile(pattern),
		weight:  1,
	}
}

func (r rule) withWeight(w uint32) rule {
	r.weight = w
	return r
}

func (r rule) asOptional() rule {
	r.optional = true
	return r
}

func (r rule) asOmitted() rule {
	r.omit = true
	return r
}

func (r rule) asNested() rule {
	r.nested = true
	return r
}

func (r rule) asExcluded() rule {
	r.exclude = true
	return r
}

// defaultRulesV1 returns the version 1 ("rules") resource rules that Apple's codesign tool
// embeds when signing an application bundle.
func defaultRulesV1() []rule {
	return []rule{
		newRule(`^version.plist$`),
		newRule(`^Resources/`),
		newRule(`^Resources/.*\.lproj/`).asOptional().withWeight(1000),
		newRule(`^Resources/Base\.lproj/`).withWeight(1010),
		newRule(`^Resources/.*\.lproj/locversion.plist$`).asOmitted().withWeight(1100),
	}
}

// defaultRulesV2 returns the version 2 ("rules2") resource rules that Apple's codesign tool
// embeds when signing an application bundle.
func defaultRulesV2() []rule {
	return []rule{
		newRule(`^.*`),
		newRule(`^[^/]+$`).asNested().withWeight(10),
		newRule(`^(Frameworks|SharedFrameworks|PlugIns|Plug-ins|XPCServices|Helpers|MacOS|Library/(Automator|Spotlight|LoginItems))/`).asNested().withWeight(10),
		newRule(`.*\.dSYM($|/)`).withWeight(11),
		newRule(`^(.*/)?\.DS_Store$`).asOmitted().withWeight(2000),
		newRule(`^Info\.plist$`).asOmitted().withWeight(20),
		newRule(`^version\.plist$`).withWeight(20),
		newRule(`^embedded\.provisionprofile$`).withWeight(20),
		newRule(`^PkgInfo$`).asOmitted().withWeight(20),
		newRule(`^Resources/`).withWeight(20),
		newRule(`^Resources/.*\.lproj/`).asOptional().withWeight(1000),
		newRule(`^Resources/Base\.lproj/`).withWeight(1010),
		newRule(`^Resources/.*\.lproj/locversion.plist$`).asOmitted().withWeight(1100),
	}
}

// findRule returns the best matching rule for the given normalized path, or nil when no
// rule matches. Exclusion rules take precedence over all other rules, then the rule with
// the highest weight wins (ties go to the earliest registered rule).
func findRule(rules []rule, normalizedPath string) *rule {
	var best *rule
	for i := range rules {
		r := &rules[i]
		if !r.pattern.MatchString(normalizedPath) {
			continue
		}
		if best == nil || betterRule(r, best) {
			best = r
		}
	}
	return best
}

func betterRule(candidate, current *rule) bool {
	if candidate.exclude != current.exclude {
		return candidate.exclude
	}
	return candidate.weight > current.weight
}

// normalizePath converts a bundle-root-relative path to the form used within the
// CodeResources file: forward slashes with any leading "Contents/" prefix removed.
func normalizePath(relPath string) string {
	p := strings.ReplaceAll(relPath, "\\", "/")
	return strings.TrimPrefix(p, "Contents/")
}

// excludePathRule creates an exclusion rule that matches exactly the given normalized path.
func excludePathRule(normalizedPath string) (rule, error) {
	re, err := regexp.Compile("^" + regexp.QuoteMeta(normalizedPath) + "$")
	if err != nil {
		return rule{}, fmt.Errorf("unable to compile exclusion rule for %q: %w", normalizedPath, err)
	}
	return rule{pattern: re, exclude: true, weight: 1}, nil
}
