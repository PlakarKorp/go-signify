package signify

import (
	"regexp"
	"strings"
	"testing"
)

// Checked with a regexp rather than golang.org/x/mod/semver: a dependency
// carried by every consumer of this library, for one assertion in a test, is
// not a good trade.
var semverRE = regexp.MustCompile(`^v\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$`)

func TestVersionIsValidSemver(t *testing.T) {
	if !semverRE.MatchString(VERSION) {
		t.Errorf("VERSION = %q is not valid semver", VERSION)
	}
}

// Version() may append build metadata, but must remain rooted at VERSION so a
// reported version is always traceable to a release.
func TestVersionReportsRelease(t *testing.T) {
	got := Version()

	if !strings.HasPrefix(got, VERSION) {
		t.Errorf("Version() = %q, want it to start with %q", got, VERSION)
	}

	if base, _, _ := strings.Cut(got, "+"); !semverRE.MatchString(base) {
		t.Errorf("Version() = %q has a non-semver base %q", got, base)
	}
}
