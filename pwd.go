// Package etcpwdparse provides straightforward functionality for loading an /etc/passwd file
// and doing lookups on its content.
//
// Remember this only looks at an /etc/passwd type file, so will work best on Linux operating systems
// and wont pick up users from LDAP and other sources.
package etcpwdparse

import (
	"fmt"
	"io/ioutil"
	"strconv"
	"strings"
)

// EtcPasswdEntry is a parsed line from the etc passwd file. It contains all 7 parts of the structure.
// Remember that the password field is encrypted or refers to an item in an alternative authentication scheme.
type EtcPasswdEntry struct {
	username string
	password string
	uid      int
	gid      int
	info     string
	homedir  string
	shell    string
}

// Username function returns the username string for the entry
func (e *EtcPasswdEntry) Username() string {
	return e.username
}

// Password function returns the encrypted password string for the entry
func (e *EtcPasswdEntry) Password() string {
	return e.password
}

// Uid function returns the user id for the entry
func (e *EtcPasswdEntry) Uid() int {
	return e.uid
}

// Gid function returns the group id for the entry
func (e *EtcPasswdEntry) Gid() int {
	return e.gid
}

// Info function returns the info string for the entry
func (e *EtcPasswdEntry) Info() string {
	return e.info
}

// Homedir function returns the home directory for the entry
func (e *EtcPasswdEntry) Homedir() string {
	return e.homedir
}

// Shell function returns the users shell
func (e *EtcPasswdEntry) Shell() string {
	return e.shell
}

// EtcPasswdCache is an object that stores a set of entries from the passwd file and
// has quick lookup functions.
type EtcPasswdCache struct {
	entries        []EtcPasswdEntry
	namemap        map[string]*EtcPasswdEntry
	idmap          map[int]*EtcPasswdEntry
	ignoreBadLines bool
}

// ParsePasswdLine is a function used to parse a 7 entry /etc/passwd line formatted line
// into a EtcPasswdEntry object.
func ParsePasswdLine(line string) (EtcPasswdEntry, error) {
	result := EtcPasswdEntry{}
	parts := strings.Split(strings.TrimSpace(line), ":")
	if len(parts) != 7 {
		return result, fmt.Errorf("Passwd line had wrong number of parts %d != 7", len(parts))
	}
	result.username = strings.TrimSpace(parts[0])
	result.password = strings.TrimSpace(parts[1])

	uid, err := strconv.Atoi(parts[2])
	if err != nil {
		return result, fmt.Errorf("Passwd line had badly formatted uid %s", parts[2])
	}
	result.uid = uid

	gid, err := strconv.Atoi(parts[3])
	if err != nil {
		return result, fmt.Errorf("Passwd line had badly formatted gid %s", parts[2])
	}
	result.gid = gid

	result.info = strings.TrimSpace(parts[4])
	result.homedir = strings.TrimSpace(parts[5])
	result.shell = strings.TrimSpace(parts[6])
	return result, nil
}

// AddEntry adds an entry object to the cache object and links it into the lookup maps.
// Overrides any existing item in the lookup maps.
func (e *EtcPasswdCache) AddEntry(entry EtcPasswdEntry) {
	e.entries = append(e.entries, entry)
	e.namemap[entry.username] = &entry
	e.idmap[entry.uid] = &entry
}

// LoadFromPath loads the struct from a file on disk and replaces the cached content.
func (e *EtcPasswdCache) LoadFromPath(path string) error {
	content, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}
	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	e.entries = make([]EtcPasswdEntry, 0)
	e.namemap = make(map[string]*EtcPasswdEntry)
	e.idmap = make(map[int]*EtcPasswdEntry)
	for _, line := range lines {
		line = strings.TrimSpace(line)
		// skip commented or empty lines
		if len(line) == 0 || strings.HasPrefix(line, "#") {
			continue
		}
		// parse the current line
		entry, err := ParsePasswdLine(line)
		if err != nil {
			if e.ignoreBadLines {
				continue
			}
			return err
		}
		e.AddEntry(entry)
	}
	return nil
}

// NewEtcPasswdCache returns an empty passwd cache.
func NewEtcPasswdCache(ignoreBadLines bool) *EtcPasswdCache {
	return &EtcPasswdCache{
		ignoreBadLines: ignoreBadLines,
	}
}

// NewLoadedEtcPasswdCache returns a loaded passwd cache in a single call.
func NewLoadedEtcPasswdCache() (*EtcPasswdCache, error) {
	result := NewEtcPasswdCache(false)
	if err := result.LoadDefault(); err != nil {
		return nil, err
	}
	return result, nil
}

// LoadDefault loads the struct from the /etc/passwd file
func (e *EtcPasswdCache) LoadDefault() error {
	return e.LoadFromPath("/etc/passwd")
}

// LookupUserByName returns the entry for the given username
func (e *EtcPasswdCache) LookupUserByName(name string) (*EtcPasswdEntry, bool) {
	entry, ok := e.namemap[name]
	return entry, ok
}

// LookupUserByUid returns the entry for the given userid
func (e *EtcPasswdCache) LookupUserByUid(id int) (*EtcPasswdEntry, bool) {
	entry, ok := e.idmap[id]
	return entry, ok
}

// UidForUsername is a shortcut function to get the user id for the given username.
// Useful when needing to chown a file.
func (e *EtcPasswdCache) UidForUsername(name string) (int, error) {
	entry, ok := e.LookupUserByName(name)
	if !ok {
		return 0, fmt.Errorf("No such user with username '%s'", name)
	}
	return entry.Uid(), nil
}

// HomeDirForUsername is a shortcut function to get the home directory for the given username.
// Useful when needing to store things in the home directory.
func (e *EtcPasswdCache) HomeDirForUsername(name string) (string, error) {
	entry, ok := e.LookupUserByName(name)
	if !ok {
		return "", fmt.Errorf("No such user with username '%s'", name)
	}
	return entry.Homedir(), nil
}

// ListEntries returns a slice containing references to all the entry objects
func (e *EtcPasswdCache) ListEntries() []*EtcPasswdEntry {
	results := make([]*EtcPasswdEntry, len(e.entries))
	for i, e := range e.entries {
		results[i] = &e
	}
	return results
}
