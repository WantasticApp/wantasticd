package cemu

import "testing"

func TestSscanfScansets(t *testing.T) {
	var got []string
	n := Sscanf("pon1,--,1,,2500", "%[^,],%[^,],%[^,],%[^,],%s", func(i int, v string) { got = append(got, v) })
	// "%[^,]" cannot match the empty 4th field: C stops there with 3.
	if n != 3 || len(got) != 3 || got[2] != "1" {
		t.Fatalf("n=%d got=%q", n, got)
	}
	if n := Sscanf("", "%s", func(int, string) {}); n != -1 {
		t.Fatalf("empty input: n=%d, want EOF(-1)", n)
	}
	got = nil
	n = Sscanf("  nameserver   8.8.8.8\n", "%s %s", func(i int, v string) { got = append(got, v) })
	if n != 2 || got[1] != "8.8.8.8" {
		t.Fatalf("n=%d got=%q", n, got)
	}
	got = nil
	n = Sscanf("a:b:c:d", "%[^:]:%[^:]:%s", func(i int, v string) { got = append(got, v) })
	if n != 3 || got[2] != "c:d" {
		t.Fatalf("n=%d got=%q", n, got)
	}
}

// The vendor parses into adjacent fixed-size stack buffers; a long field
// written later spills into a neighbour. Frame reproduces that.
func TestFrameOverlap(t *testing.T) {
	f := NewFrame(0x100)
	// formGetVlanList: vlanId at fp-0x64 (8 bytes), threeLayersEn at fp-0x68
	// (4 bytes below it) is written after vlanId.
	f.Sscanf("10,12345", "%[^,],%s", 0x64, 0x68)
	if got := f.Str(0x64); got != "5" {
		t.Fatalf("vlanId after overlap = %q, want %q", got, "5")
	}
	if got := f.Str(0x68); got != "12345" {
		t.Fatalf("threeLayersEn = %q", got)
	}
	f.Zero(0x68, 12)
	if f.Str(0x64) != "" || f.Str(0x68) != "" {
		t.Fatal("Zero did not clear")
	}
	f.Strncpy(0x20, "abcdef", 3)
	if f.Str(0x20) != "abc" {
		t.Fatalf("strncpy: %q", f.Str(0x20))
	}
}

func TestStrtok(t *testing.T) {
	got := Strtok("\n\na\n\nb\nc\n", "\n")
	if len(got) != 3 || got[0] != "a" || got[2] != "c" {
		t.Fatalf("%q", got)
	}
	if len(Strtok("", ",")) != 0 || len(Strtok(",,,", ",")) != 0 {
		t.Fatal("empty tokens returned")
	}
}

func TestJSONPrint(t *testing.T) {
	o := Object()
	o.AddString("a", "x\"y\\\n\x01é")
	o.AddString("a", "dup")
	arr := Array()
	arr.AddString("ignored", "pon1")
	o.AddItem("l", arr)
	o.AddNumber("n", 7)
	o.AddNumber("f", 1.5)
	want := `{"a":"x\"y\\\n\u0001é","a":"dup","l":["pon1"],"n":7,"f":1.5}`
	if got := string(o.Print()); got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

func TestSscanfWidthAndIntegers(t *testing.T) {
	f := NewFrame(0x40)
	if n := f.Sscanf("0011-2233-4455", "%4s-%4s-%4s", 0x10, 0x20, 0x30); n != 3 || f.Str(0x10) != "0011" || f.Str(0x20) != "2233" || f.Str(0x30) != "4455" {
		t.Fatalf("width: n=%d %q %q %q", n, f.Str(0x10), f.Str(0x20), f.Str(0x30))
	}
	if n := f.Sscanf("abcdef", "%4s%s", 0x10, 0x20); n != 2 || f.Str(0x10) != "abcd" || f.Str(0x20) != "ef" {
		t.Fatalf("width split: %q %q", f.Str(0x10), f.Str(0x20))
	}
	if n := f.Sscanf(" 90061 x", "%u%s", 0x10, 0x20); n != 2 || f.U32(0x10) != 90061 || f.Str(0x20) != "x" {
		t.Fatalf("%%u: n=%d %d", n, f.U32(0x10))
	}
	if n := f.Sscanf("-1", "%d%s", 0x10, 0x20); n != 1 || int32(f.U32(0x10)) != -1 {
		t.Fatalf("%%d: n=%d %d", n, int32(f.U32(0x10)))
	}
	if n := f.Sscanf("ERROR", "%d%s", 0x10, 0x20); n != 0 {
		t.Fatalf("no digits: n=%d", n)
	}
}
