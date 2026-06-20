package yara

import "testing"

// The genuine EICAR antivirus test signature — a real, standardized string every
// scanner is meant to flag, so the test uses no fabricated malware.
const eicar = `X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

func TestScanEICAR(t *testing.T) {
	eng, err := Compile(`
rule EICAR_Test_File {
    meta:
        description = "Standard EICAR antivirus test signature"
    strings:
        $marker = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
    condition:
        $marker
}`)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if got := eng.Scan([]byte(eicar)); len(got) != 1 || got[0] != "EICAR_Test_File" {
		t.Fatalf("scan(eicar) = %v, want [EICAR_Test_File]", got)
	}
	if got := eng.Scan([]byte("entirely benign file content")); len(got) != 0 {
		t.Errorf("scan(benign) = %v, want none", got)
	}
}

func TestScanHexWildcardAndNocase(t *testing.T) {
	eng, err := Compile(`
rule ELF_Miner {
    strings:
        $elf  = { 7F 45 4C 46 ?? 01 }
        $pool = "stratum+tcp" nocase
    condition:
        $elf and $pool
}`)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	// ELF magic, a wildcard byte (0x02), the 0x01 anchor, then an upper-case pool URL.
	sample := append([]byte{0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01}, []byte("STRATUM+TCP://x")...)
	if got := eng.Scan(sample); !contains(got, "ELF_Miner") {
		t.Errorf("scan = %v, want ELF_Miner", got)
	}
	// Wrong anchor byte after the wildcard -> hex pattern must not match.
	bad := append([]byte{0x7F, 0x45, 0x4C, 0x46, 0x02, 0x09}, []byte("stratum+tcp")...)
	if got := eng.Scan(bad); contains(got, "ELF_Miner") {
		t.Errorf("scan(bad anchor) = %v, should not match", got)
	}
}

func TestQuantifiersAndBoolean(t *testing.T) {
	eng, err := Compile(`
rule Webshell {
    strings:
        $php  = "<?php"
        $sys  = "system("
        $eval = "eval("
    condition:
        $php and 2 of them
}
rule NeedsAll {
    strings:
        $a = "aaa"
        $b = "bbb"
    condition:
        all of them
}`)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if got := eng.Scan([]byte(`<?php system($_GET['c']); eval($x); ?>`)); !contains(got, "Webshell") {
		t.Errorf("webshell not matched: %v", got)
	}
	// Only $php present: "2 of them" fails, so Webshell must not fire.
	if got := eng.Scan([]byte(`<?php echo "hello"; ?>`)); contains(got, "Webshell") {
		t.Errorf("benign php matched Webshell: %v", got)
	}
	if got := eng.Scan([]byte("aaa and bbb")); !contains(got, "NeedsAll") {
		t.Errorf("all-of-them not matched: %v", got)
	}
	if got := eng.Scan([]byte("only aaa")); contains(got, "NeedsAll") {
		t.Errorf("partial match fired all-of-them: %v", got)
	}
}

func TestCompileErrors(t *testing.T) {
	for _, src := range []string{
		`garbage`,                                       // not a rule
		`rule { condition: true }`,                      // missing name
		`rule X { strings: $a = "x" }`,                  // missing condition
		`rule X { strings: $a = { ZZ } condition: $a }`, // invalid hex
		`rule X { condition: $a or }`,                   // dangling operator
	} {
		if _, err := Compile(src); err == nil {
			t.Errorf("expected a compile error for %q", src)
		}
	}
}
