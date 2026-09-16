package plugin

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/bomly-dev/bomly-sdk/testkit"

	sdkmodel "github.com/bomly-dev/bomly-sdk/model"
	sdkplugin "github.com/bomly-dev/bomly-sdk/plugin"
)

func jvmProjectFixture(name string) string {
	path, err := filepath.Abs(filepath.Join("testdata", "projects", name))
	if err != nil {
		return filepath.Join("testdata", "projects", name)
	}
	return path
}

func TestLibraryRunnerWalksJVMTestdata(t *testing.T) {
	got, err := NewRunner(nil).Run(context.Background(), jvmProjectFixture("dynamic"))
	if err != nil {
		t.Fatal(err)
	}
	for _, coord := range []string{
		"com.fasterxml.jackson.core:jackson-databind",
		"org.apache.logging.log4j:log4j-api",
		"org.apache.logging.log4j:log4j-core",
	} {
		if _, ok := got.ImportedArtifacts[coord]; !ok {
			t.Fatalf("missing artifact %q: %v", coord, got.ImportedArtifacts)
		}
	}
	if _, ok := got.ImportedArtifacts["com.google.guava:guava"]; ok {
		t.Fatalf("nested child module import leaked into parent scan: %v", got.ImportedArtifacts)
	}
	if _, ok := got.RawImports["com.fasterxml.jackson.databind.ObjectMapper"]; !ok {
		t.Fatalf("raw imports = %v", got.RawImports)
	}
	if got.SourceFiles != 1 || !got.DynamicImportsDetected {
		t.Fatalf("result = %+v, want one source and dynamic imports", got)
	}
}

func TestJVMDynamicImportDetectionFromTestdata(t *testing.T) {
	if !detectDynamicImports(jvmProjectFixture("dynamic")) {
		t.Fatal("dynamic fixture was not detected")
	}
	if detectDynamicImports(jvmProjectFixture("static")) {
		t.Fatal("literal reflection and ignored build output should remain static")
	}
}

func TestJVMDescriptorAndRunnerResult(t *testing.T) {
	a := Analyzer{}
	if err := a.Ready(context.Background(), sdkplugin.AnalyzeRequest{}); err != nil || a.Descriptor().Name != Name {
		t.Fatalf("descriptor = %+v ready_err=%v", a.Descriptor(), a.Ready(context.Background(), sdkplugin.AnalyzeRequest{}))
	}
	if !(RunnerResult{SourceFiles: 1}).hasResult() || (RunnerResult{}).hasResult() {
		t.Fatal("runner result actionability mismatch")
	}
}

func TestJVMStandaloneApplyRunnerResult(t *testing.T) {
	const purl = "pkg:maven/com.fasterxml.jackson.core/jackson-databind"
	g := sdkmodel.New()
	pkg := testkit.MustDependencyCoords(t, sdkmodel.Coordinates{Name: "jackson-databind",
		Org:       "com.fasterxml.jackson.core",
		Ecosystem: sdkmodel.EcosystemMaven,
		PURL:      purl})
	if err := g.AddNode(pkg); err != nil {
		t.Fatal(err)
	}
	reg := sdkmodel.NewPackageRegistry()
	reg.Ensure(purl).Vulnerabilities = []sdkmodel.Vulnerability{{ID: "GHSA-1"}}
	req := sdkplugin.AnalyzeRequest{Graph: g, Registry: reg}
	root := jvmProjectFixture("dynamic")
	got := applyRunnerResult(req, sdkmodel.NewRootAttributor([]string{root}, g), root, RunnerResult{
		ImportedArtifacts: map[string]struct{}{"com.fasterxml.jackson.core:jackson-databind": {}},
		SourceFiles:       1,
	}, time.Time{})
	vulns := reg.Ensure(purl).Vulnerabilities
	if got.reachable != 1 || vulns[0].Reachability == nil || vulns[0].Reachability.Status != sdkmodel.ReachabilityReachable {
		t.Fatalf("outcome = %+v reachability=%+v", got, vulns[0].Reachability)
	}
}

func TestJVMFailureReasons(t *testing.T) {
	tests := map[string]string{
		"runner not implemented":              "missing-toolchain",
		"project dir not accessible":          "no-project-root",
		"context deadline exceeded":           "cancelled",
		"unexpected source scanner condition": "runner-error",
	}
	for message, want := range tests {
		if got := failureReason(errors.New(message)); got != want {
			t.Fatalf("failureReason(%q) = %q, want %q", message, got, want)
		}
	}
	if got := failureReason(nil); got != "" {
		t.Fatalf("failureReason(nil) = %q", got)
	}
	runner := NewRunner(nil)
	if runner.Name() != "library" || runner.Version() != runnerSchemaVersion {
		t.Fatalf("runner = %q version=%q", runner.Name(), runner.Version())
	}
}
