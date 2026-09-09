package plugin

import (
	"path/filepath"
	"testing"
	"time"

	model "github.com/bomly-dev/bomly-sdk"
	"github.com/bomly-dev/bomly-sdk/testkit"
)

// jvmNodeIn builds one JVM dependency node whose declaration site is the build
// manifest of projectRoot.
func jvmNodeIn(t *testing.T, group, artifact, version, projectRoot string) *model.DependencyNode {
	t.Helper()
	dep := testkit.MustDependencyCoords(t, model.Coordinates{
		Name: artifact, Org: group, Version: version,
		Ecosystem: model.EcosystemMaven, PackageManager: "maven",
	})
	if projectRoot != "" {
		dep.Locations = []model.PackageLocation{{RealPath: filepath.Join(projectRoot, "pom.xml")}}
	}
	dep.PackageRef = dep.NodeID()
	return dep
}

func jvmGraph(t *testing.T, nodes []*model.DependencyNode, ids []string) (*model.Graph, *model.PackageRegistry) {
	t.Helper()
	g := model.New()
	registry := model.NewPackageRegistry()
	for i, node := range nodes {
		if err := g.AddNode(node); err != nil {
			t.Fatalf("AddNode(%s): %v", node.NodeID(), err)
		}
		pkg := registry.Ensure(node.PackageRef)
		pkg.Vulnerabilities = append(pkg.Vulnerabilities, model.Vulnerability{ID: ids[i], Source: "osv"})
	}
	return g, registry
}

func jvmReachability(t *testing.T, registry *model.PackageRegistry, purl string) *model.Reachability {
	t.Helper()
	pkg, ok := registry.Get(purl)
	if !ok || pkg == nil || len(pkg.Vulnerabilities) == 0 {
		t.Fatalf("no vulnerability for %q", purl)
	}
	return pkg.Vulnerabilities[0].Reachability
}

func jvmRoots(r *model.Reachability) []string {
	if r == nil {
		return nil
	}
	roots := make([]string, 0, len(r.Evidence))
	for _, e := range r.Evidence {
		roots = append(roots, e.ModuleRoot)
	}
	return roots
}

// TestEvidenceIsKeyedByTheProjectRootThatEstablishedIt is the core of row 2.8.
//
// An artifact declared by the api module must not collect the web module's
// finding. Before attribution was real, packageBelongsToProjectRoot ended in an
// unconditional `return true`, so every JVM package took every root's answer —
// including an "unreachable" from a build it was never on the classpath of.
func TestEvidenceIsKeyedByTheProjectRootThatEstablishedIt(t *testing.T) {
	workspace := t.TempDir()
	apiRoot := filepath.Join(workspace, "api")
	webRoot := filepath.Join(workspace, "web")

	apiDep := jvmNodeIn(t, "com.fasterxml.jackson.core", "jackson-databind", "2.15.0", apiRoot)
	webDep := jvmNodeIn(t, "org.apache.logging.log4j", "log4j-core", "2.17.1", webRoot)
	g, registry := jvmGraph(t, []*model.DependencyNode{apiDep, webDep}, []string{"GHSA-1", "GHSA-2"})
	req := model.AnalyzeRequest{Graph: g, Registry: registry}

	attributor := model.NewRootAttributor([]string{apiRoot, webRoot}, g)
	for _, root := range []string{apiRoot, webRoot} {
		applyImportedArtifactSeeds(req, attributor, root, nil, false, time.Time{})
	}

	for _, tc := range []struct {
		dep  *model.DependencyNode
		want string
	}{{apiDep, apiRoot}, {webDep, webRoot}} {
		roots := jvmRoots(jvmReachability(t, registry, tc.dep.PackageRef))
		if len(roots) != 1 || roots[0] != tc.want {
			t.Errorf("%s evidence roots = %v, want exactly [%s]", tc.dep.Name, roots, tc.want)
		}
	}
}

// TestEvidenceNeverNamesAnOccurrenceNode records the judgement row 2.8 asks
// for: jvmreach speaks at module-root granularity and no lower.
//
// Its seed set is keyed by "group:artifact" with the classifier stripped, so
// "jackson-databind" and "jackson-databind:tests" — two distinct graph nodes
// the Maven detector deliberately keeps apart — are one key here and are
// decided together. Naming one of them as the occurrence would publish a
// precision the analysis never established.
func TestEvidenceNeverNamesAnOccurrenceNode(t *testing.T) {
	root := filepath.Join(t.TempDir(), "api")

	main := jvmNodeIn(t, "com.fasterxml.jackson.core", "jackson-databind", "2.15.0", root)
	tests := jvmNodeIn(t, "com.fasterxml.jackson.core", "jackson-databind:tests", "2.15.0", root)
	g, registry := jvmGraph(t, []*model.DependencyNode{main, tests}, []string{"GHSA-1", "GHSA-1"})

	applyImportedArtifactSeeds(model.AnalyzeRequest{Graph: g, Registry: registry},
		model.NewRootAttributor([]string{root}, g), root,
		map[string]int{canonicalCoord("com.fasterxml.jackson.core", "jackson-databind"): 0}, false, time.Time{})

	for _, dep := range []*model.DependencyNode{main, tests} {
		evidence := jvmReachability(t, registry, dep.PackageRef).Evidence
		if len(evidence) != 1 {
			t.Fatalf("%s evidence = %d entries, want 1", dep.Name, len(evidence))
		}
		if evidence[0].Status != model.ReachabilityReachable {
			t.Errorf("%s status = %q, want reachable: the classifier variant shares the seed key",
				dep.Name, evidence[0].Status)
		}
		if evidence[0].ModuleRoot != root {
			t.Errorf("%s module root = %q, want %q: the floor is mandatory", dep.Name, evidence[0].ModuleRoot, root)
		}
		if got := evidence[0].DependencyRefs; len(got) != 0 {
			t.Errorf("%s refs = %v; the coordinate-keyed seed set decided both nodes together", dep.Name, got)
		}
	}
}

// TestFailedProjectRootStillContributesUnknownEvidence pins the safety half in
// the failure path: one root finding nothing must not speak for a workspace
// whose other root was never analyzed.
func TestFailedProjectRootStillContributesUnknownEvidence(t *testing.T) {
	workspace := t.TempDir()
	apiRoot := filepath.Join(workspace, "api")
	webRoot := filepath.Join(workspace, "web")

	dep := jvmNodeIn(t, "org.apache.logging.log4j", "log4j-core", "2.17.1", apiRoot)
	dep.Locations = append(dep.Locations, model.PackageLocation{
		RealPath: filepath.Join(webRoot, "pom.xml"),
	})
	g, registry := jvmGraph(t, []*model.DependencyNode{dep}, []string{"GHSA-1"})
	req := model.AnalyzeRequest{Graph: g, Registry: registry}

	attributor := model.NewRootAttributor([]string{apiRoot, webRoot}, g)
	applyImportedArtifactSeeds(req, attributor, apiRoot, nil, false, time.Time{})
	annotateProjectUnknown(req, attributor, webRoot, "missing-toolchain", time.Time{})

	r := jvmReachability(t, registry, dep.PackageRef)
	if len(r.Evidence) != 2 {
		t.Fatalf("evidence = %d entries (%v), want one per project root", len(r.Evidence), jvmRoots(r))
	}
	if r.Status != model.ReachabilityUnknown {
		t.Errorf("summary = %q, want unknown: one root was never analyzed", r.Status)
	}
	if r.Reason == "" {
		t.Error("an unknown summary must still explain itself")
	}
}

// TestSiteOutsideEveryAnalyzedRootIsNotAbsence separates the two ways a path
// can fail to match. A site under another analyzed root is evidence the
// package belongs elsewhere; a site under no analyzed root at all — a local
// Maven repository, a Gradle cache — says nothing, and reading it as absence
// would silently drop the finding.
func TestSiteOutsideEveryAnalyzedRootIsNotAbsence(t *testing.T) {
	root := filepath.Join(t.TempDir(), "api")
	m2 := filepath.Join(t.TempDir(), ".m2", "repository")

	dep := jvmNodeIn(t, "org.apache.logging.log4j", "log4j-core", "2.17.1", m2)
	g, registry := jvmGraph(t, []*model.DependencyNode{dep}, []string{"GHSA-1"})

	applyImportedArtifactSeeds(model.AnalyzeRequest{Graph: g, Registry: registry},
		model.NewRootAttributor([]string{root}, g), root, nil, false, time.Time{})

	r := jvmReachability(t, registry, dep.PackageRef)
	if r == nil || len(r.Evidence) != 1 {
		t.Fatalf("evidence = %v; a site outside every analyzed root is not absence", jvmRoots(r))
	}
	if r.Evidence[0].ModuleRoot != root {
		t.Errorf("module root = %q, want %q", r.Evidence[0].ModuleRoot, root)
	}
}

// TestDeclaredRootsAreOnlyTrustedWhenTheyShareOurVocabulary guards the
// degradation path. Detectors record the root they resolved from and this
// analyzer derives roots from the filesystem; when the spellings never
// overlap, a non-match means they are speaking past each other, and dropping
// the node would lose the finding outright.
func TestDeclaredRootsAreOnlyTrustedWhenTheyShareOurVocabulary(t *testing.T) {
	root := filepath.Join(t.TempDir(), "api")
	dep := jvmNodeIn(t, "org.apache.logging.log4j", "log4j-core", "2.17.1", "")
	dep.Locations = []model.PackageLocation{{ModuleRoot: "modules/api"}}
	g, registry := jvmGraph(t, []*model.DependencyNode{dep}, []string{"GHSA-1"})

	applyImportedArtifactSeeds(model.AnalyzeRequest{Graph: g, Registry: registry},
		model.NewRootAttributor([]string{root}, g), root, nil, false, time.Time{})

	if r := jvmReachability(t, registry, dep.PackageRef); r == nil || len(r.Evidence) == 0 {
		t.Fatal("evidence was dropped for a root vocabulary mismatch; the finding is lost")
	}
}

// TestAttributorCalibratesOnOverlap pins the calibration on its own, so both
// halves of the rule hold independently of a full analysis pass.
func TestAttributorCalibratesOnOverlap(t *testing.T) {
	node := jvmNodeIn(t, "org.apache.logging.log4j", "log4j-core", "2.17.1", "")
	node.Locations = []model.PackageLocation{{ModuleRoot: "/ws/api"}}
	g := model.New()
	if err := g.AddNode(node); err != nil {
		t.Fatal(err)
	}

	shared := model.NewRootAttributor([]string{"/ws/api", "/ws/web"}, g)
	if got := shared.Attribute(node, "/ws/api"); got != model.AttributedToSite {
		t.Errorf("attribute(own root) = %v, want attributed-to-site", got)
	}
	if got := shared.Attribute(node, "/ws/web"); got != model.AttributedElsewhere {
		t.Errorf("attribute(other root) = %v, want attributed-elsewhere", got)
	}

	foreign := model.NewRootAttributor([]string{"/other/one"}, g)
	if got := foreign.Attribute(node, "/other/one"); got != model.AttributedToRootOnly {
		t.Errorf("attribute under a foreign vocabulary = %v, want attributed-to-root-only", got)
	}
}
