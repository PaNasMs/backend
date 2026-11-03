package modulelifecycle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"strings"

	"golang.org/x/sys/unix"
	"panasms.local/backend/internal/systemops"
)

func createDirectoryAt(parent *os.File, name string, mode uint32, owner uint32, exclusive bool) (*os.File, error) {
	err := unix.Mkdirat(int(parent.Fd()), name, mode)
	created := err == nil
	if err != nil && (err != unix.EEXIST || exclusive) {
		return nil, err
	}
	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	var stat unix.Stat_t
	if err = unix.Fstat(fd, &stat); err == nil && (stat.Uid != owner || stat.Mode&0022 != 0) {
		err = reject("Module staging permissions are unsafe")
	}
	if err == nil && created {
		err = file.Chmod(os.FileMode(mode))
	}
	if err == nil && created {
		err = parent.Sync()
	}
	if err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}

type checkpointReader struct {
	ctx      context.Context
	reporter *systemops.Reporter
	source   io.Reader
}

func (r checkpointReader) Read(buffer []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	if r.reporter != nil {
		if err := r.reporter.Checkpoint(); err != nil {
			return 0, err
		}
	}
	return r.source.Read(buffer)
}

func extractFile(ctx context.Context, parent *os.File, name string, source io.Reader, size uint64, digest string, mode uint32, owner uint32, reporter *systemops.Reporter) error {
	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, mode)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	var stat unix.Stat_t
	if err = unix.Fstat(fd, &stat); err != nil {
		return err
	}
	if stat.Uid != owner || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 {
		return reject("Module staging permissions are unsafe")
	}
	hash := sha256.New()
	count, err := io.CopyBuffer(io.MultiWriter(file, hash), checkpointReader{ctx, reporter, io.LimitReader(source, int64(size)+1)}, make([]byte, 64<<10))
	if err != nil {
		return err
	}
	if uint64(count) != size || hex.EncodeToString(hash.Sum(nil)) != digest {
		return reject("Module archive changed during extraction")
	}
	if err = file.Chmod(os.FileMode(mode)); err != nil {
		return err
	}
	if err = file.Sync(); err != nil {
		return err
	}
	return parent.Sync()
}

func (s lifecycle) extract(ctx context.Context, plan *prepared, state *transaction, reporter *systemops.Reporter) error {
	if err := state.validate(s.owner); err != nil {
		return err
	}
	if state.Schema != 1 || state.Phase != "staging" || state.Committed {
		return reject("Invalid module extraction phase")
	}
	stage, err := s.transactionDirectory()
	if err != nil {
		return err
	}
	defer stage.Close()
	// A dot-prefixed namespace cannot collide with an installed module or the
	// old reader's old-ID backup names.
	newRoot, err := createDirectoryAt(stage, ".new", 0700, s.owner, true)
	if err != nil {
		return err
	}
	defer newRoot.Close()
	for _, id := range plan.order {
		manifest := plan.available[id]
		if manifest == nil {
			continue
		}
		if err = identifier(id); err != nil {
			return err
		}
		module, err := createDirectoryAt(newRoot, id, 0755, s.owner, true)
		if err != nil {
			return err
		}
		payload, _ := object(manifest, "files")
		for _, relative := range names(payload) {
			components := strings.Split(relative, "/")
			parent := module
			opened := []*os.File{}
			for _, component := range components[:len(components)-1] {
				parent, err = createDirectoryAt(parent, component, 0755, s.owner, false)
				if err != nil {
					break
				}
				opened = append(opened, parent)
			}
			if err == nil {
				file := plan.bundle.files["modules/"+id+"/"+relative]
				if file == nil {
					err = reject("Module payload is missing")
				} else {
					reader, openErr := file.Open()
					err = openErr
					if err == nil {
						mode := uint32(0644)
						if relative == "bin/server" {
							mode = 0755
						}
						err = extractFile(ctx, parent, components[len(components)-1], reader, file.UncompressedSize64, payload[relative].(string), mode, s.owner, reporter)
						reader.Close()
					}
				}
			}
			for _, directory := range opened {
				directory.Close()
			}
			if err != nil {
				module.Close()
				return err
			}
		}
		if err = module.Sync(); err != nil {
			module.Close()
			return err
		}
		module.Close()
		identity, err := directoryAt(newRoot, id, s.owner)
		if err != nil {
			return err
		}
		payloadState := state.Payloads[id]
		payloadState.Staged = identity
		state.Payloads[id] = payloadState
		if err = s.saveTransaction(state); err != nil {
			return err
		}
	}
	return nil
}
