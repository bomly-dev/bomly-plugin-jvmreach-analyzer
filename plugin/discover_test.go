package plugin

import (
	"os"
	"path/filepath"
	"testing"

	sdkplugin "github.com/bomly-dev/bomly-sdk/plugin"
)

// A Kubernetes Secret or ConfigMap mount names its data directory "..data",
// so a directory whose name merely begins with two dots is real and must be
// discovered; only a ".." path element escapes the root.

func TestPathContainsRootReadsEscapeAsAPathElement(t *testing.T) {
	root := filepath.FromSlash("/app")
	for _, tc := range []struct {
		path string
		want bool
	}{
		{"/app", true},
		{"/app/..data", true},
		{"/app/..data/pom.xml", true},
		{"/app/...", true},
		{"/app/sub/..data", true},
		{"/", false},
		{"/other", false},
		{"/app/../other", false},
		{"/apple", false},
		{"relative/path", false},
	} {
		if got := pathContainsRoot(filepath.FromSlash(tc.path), root); got != tc.want {
			t.Errorf("pathContainsRoot(%q, %q) = %v, want %v", tc.path, root, got, tc.want)
		}
	}
}

func TestDiscoverMavenModulesFollowsDotDotNamedDirectory(t *testing.T) {
	root := t.TempDir()
	writeJVMFixture(t, root, "pom.xml", `<project><groupId>com.example</groupId><artifactId>root</artifactId><modules><module>..data</module><module>../outside</module></modules></project>`)
	writeJVMFixture(t, root, "..data/pom.xml", `<project><artifactId>secrets</artifactId></project>`)
	writeJVMFixture(t, filepath.Dir(root), "outside/pom.xml", `<project><artifactId>outside</artifactId></project>`)

	seen := make(map[string]jvmModule)
	discoverMavenModules(root, "", seen)

	if module, ok := seen[filepath.Join(root, "..data")]; !ok || module.Coord != "com.example:secrets" {
		t.Fatalf("..data module = %+v (found %v), want com.example:secrets discovered; seen = %+v", module, ok, seen)
	}
	if _, ok := seen[filepath.Join(filepath.Dir(root), "outside")]; ok {
		t.Fatalf("module outside the root was discovered: %+v", seen)
	}
}

func TestReadGradleModulesIncludesDotDotNamedDirectory(t *testing.T) {
	root := t.TempDir()
	writeJVMFixture(t, root, "settings.gradle", "include ':secrets'\nproject(':secrets').projectDir = file('..data')\ninclude ':escape'\nproject(':escape').projectDir = file('../outside')\n")

	dirs := make(map[string]bool)
	for _, module := range readGradleModules(root) {
		dirs[module.Dir] = true
	}
	if !dirs[filepath.Join(root, "..data")] {
		t.Fatalf("gradle modules = %v, want %s", dirs, filepath.Join(root, "..data"))
	}
	if dirs[filepath.Join(filepath.Dir(root), "outside")] {
		t.Fatalf("gradle module outside the root was discovered: %v", dirs)
	}
}

// TestDiscoverModuleHierarchiesFollowsKubernetesDataMount builds the layout a
// mounted ConfigMap actually has -- "..data" is a symlink to a timestamped
// directory -- and checks the module in it is discovered end to end.
func TestDiscoverModuleHierarchiesFollowsKubernetesDataMount(t *testing.T) {
	root := t.TempDir()
	writeJVMFixture(t, root, "pom.xml", `<project><groupId>com.example</groupId><artifactId>root</artifactId><modules><module>..data</module></modules></project>`)
	writeJVMFixture(t, root, "..2026_09_07_02_56_10.000000001/pom.xml", `<project><artifactId>mounted</artifactId></project>`)
	if err := os.Symlink("..2026_09_07_02_56_10.000000001", filepath.Join(root, "..data")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	hierarchies := discoverModuleHierarchies(sdkplugin.AnalyzeRequest{ProjectPath: root})
	if len(hierarchies) != 1 {
		t.Fatalf("hierarchies = %+v, want one", hierarchies)
	}
	for _, module := range hierarchies[0].Modules {
		if module.Dir == filepath.Join(root, "..data") && module.Coord == "com.example:mounted" {
			return
		}
	}
	t.Fatalf("modules = %+v, want com.example:mounted at %s", hierarchies[0].Modules, filepath.Join(root, "..data"))
}
