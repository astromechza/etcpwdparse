package etcpwdparse

import (
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"testing"
)

const fakePwdContent = `
# commented line

# empty line above
root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/spool/mail:/sbin/nologin
operator:x:11:0:operator:/root:/sbin/nologin
games:x:12:100:games:/usr/games:/sbin/nologin
ftp:x:14:50:FTP User:/var/ftp:/sbin/nologin
nobody:x:99:99:Nobody:/:/sbin/nologin
`

func TestFull(t *testing.T) {
	tempDir, _ := ioutil.TempDir("", "etc")
	pwFile := path.Join(tempDir, "passwd")
	err := ioutil.WriteFile(pwFile, []byte(fakePwdContent), 0644)
	if err != nil {
		t.Fatalf("Should not have failed: %s", err)
	}
	defer os.Remove(pwFile)

	cache := NewEtcPasswdCache(false)
	err = cache.LoadFromPath(pwFile)
	if err != nil {
		t.Fatalf("Should not have failed: %s", err)
	}

	rootEntry, _ := cache.LookupUserByName("root")
	if rootEntry.Username() != "root" {
		t.Fatalf("%s != root", rootEntry.Username())
	}
	if rootEntry.Password() != "x" {
		t.Fatalf("%s != x", rootEntry.Password())
	}
	if rootEntry.Uid() != 0 {
		t.Fatalf("%d != 0", rootEntry.Uid())
	}
	if rootEntry.Gid() != 0 {
		t.Fatalf("%d != 0", rootEntry.Gid())
	}
	if rootEntry.Info() != "root" {
		t.Fatalf("%s != root", rootEntry.Info())
	}
	if rootEntry.Homedir() != "/root" {
		t.Fatalf("%s != /root", rootEntry.Homedir())
	}
	if rootEntry.Shell() != "/bin/bash" {
		t.Fatalf("%s != /bin/bash", rootEntry.Shell())
	}

	nobodyEntry, _ := cache.LookupUserByUid(99)
	if nobodyEntry.Username() != "nobody" {
		t.Fatalf("%s != nobody", nobodyEntry.Shell())
	}

	uid, _ := cache.UidForUsername("mail")
	if uid != 8 {
		t.Fatalf("%d != 8", uid)
	}

	hd, _ := cache.HomeDirForUsername("games")
	if hd != "/usr/games" {
		t.Fatalf("%s != /usr/games", hd)
	}
}

func Example() {
	// load the cache from the /etc/passwd file
	cache, err := NewLoadedEtcPasswdCache()
	if err != nil {
		panic(err)
	}

	// look up the current user
	entry, _ := cache.LookupUserByUid(os.Getuid())

	// print some result
	fmt.Printf("Your current user is %s and your homedir is %s\n", entry.Username(), entry.Homedir())
}
