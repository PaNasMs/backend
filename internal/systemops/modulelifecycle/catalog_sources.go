package modulelifecycle

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/sys/unix"
	"panasms.local/backend/internal/systemops"
)

const officialURL = "https://panasms.github.io/module-registry/"
const officialID = "panasms-official"
const sourceIntent = ".source-change.json"
const maxSourceState = 256 << 10

func officialSource() map[string]any {
	return map[string]any{"id": officialID, "url": officialURL, "official": true, "signers": []any{"panasms-local", "panasms-ci"}}
}

func sourceSpecs(raw []map[string]any) []source {
	sources := make([]source, 0, len(raw))
	for _, m := range raw {
		src := source{ID: text(m, "id"), URL: text(m, "url"), Fingerprint: text(m, "fingerprint")}
		src.Official, _ = m["official"].(bool)
		if arr, ok := m["signers"].([]any); ok {
			for _, v := range arr {
				s, _ := v.(string)
				src.Signers = append(src.Signers, s)
			}
		}
		sources = append(sources, src)
	}
	return sources
}

func (c catalogService) sources() ([]map[string]any, error) {
	dir, err := trustedDirectory(filepath.Dir(c.config), c.owner)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	raw, err := readOwnedAt(dir, filepath.Base(c.config), c.owner, maxSourceState)
	if errors.Is(err, unix.ENOENT) {
		return []map[string]any{officialSource()}, nil
	}
	if err != nil {
		return nil, err
	}
	var configured []map[string]any
	if systemops.Decode(raw, &configured) != nil || configured == nil || len(configured) > 16 {
		return nil, reject("Invalid module repository configuration")
	}
	ids, urls := map[string]bool{}, map[string]bool{}
	for _, src := range sourceSpecs(configured) {
		if identifier(src.ID) != nil || ids[src.ID] || urls[src.URL] || !strings.HasSuffix(src.URL, "/") || len(src.Signers) == 0 || (src.Fingerprint != "" && (!archiveDigest.MatchString(src.Fingerprint) || len(src.Signers) != 1)) {
			return nil, reject("Invalid module repository configuration")
		}
		if _, err = repositoryURL(src.URL, false); err != nil {
			return nil, err
		}
		for _, signer := range src.Signers {
			if !signerPattern.MatchString(signer) {
				return nil, reject("Invalid module repository publisher")
			}
		}
		ids[src.ID], urls[src.URL] = true, true
	}
	return configured, nil
}

func publicFingerprint(public ed25519.PublicKey) string {
	der, _ := x509.MarshalPKIXPublicKey(public)
	digest := sha256.Sum256(der)
	return hex.EncodeToString(digest[:])
}

func discoveryKey(raw []byte) (ed25519.PublicKey, error) {
	block, rest := pem.Decode(raw)
	msg := "The repository must use an Ed25519 public key"
	if block == nil || block.Type != "PUBLIC KEY" || len(block.Headers) != 0 || strings.TrimSpace(string(rest)) != "" {
		return nil, reject(msg)
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	public, ok := key.(ed25519.PublicKey)
	if err != nil || !ok {
		return nil, reject(msg)
	}
	return public, nil
}

func (c catalogService) discover(ctx context.Context, input string) (map[string]any, []byte, error) {
	u, err := repositoryURL(input, false)
	if err != nil {
		return nil, nil, err
	}
	u.Host = strings.ToLower(u.Host)
	base := strings.TrimRight(u.String(), "/") + "/"
	if base == officialURL {
		return officialSource(), nil, nil
	}
	gen, err := c.fetch(ctx, base)
	if err != nil {
		return nil, nil, err
	}
	sig, err := catalogSigner(gen.Envelope)
	if err != nil {
		return nil, nil, err
	}
	if strings.HasPrefix(sig.Signer, "panasms-") {
		return nil, nil, reject("Choose a unique repository publisher ID")
	}
	raw, err := c.download(ctx, base+"keys/"+sig.Signer+".pem", 8192, metadataDownload)
	if err != nil {
		return nil, nil, err
	}
	public, err := discoveryKey(raw)
	if err != nil {
		return nil, nil, err
	}
	digest := publicFingerprint(public)
	src := source{URL: base, Signers: []string{sig.Signer}, Fingerprint: digest}
	if err = verifyCatalog(gen, src, func(string) (ed25519.PublicKey, error) { return public, nil }); err != nil {
		return nil, nil, err
	}
	var data struct{ ID string }
	if systemops.Decode(gen.Raw, &data) != nil || identifier(data.ID) != nil || data.ID == officialID {
		return nil, nil, reject("Choose a unique repository ID")
	}
	src.ID = data.ID
	if _, err = parseCatalog(gen.Raw, src); err != nil {
		return nil, nil, err
	}
	old, err := c.keyBytes(sig.Signer)
	if err != nil {
		return nil, nil, err
	}
	if old != nil {
		existing, err := readPublicKey(c.keys, sig.Signer, c.owner)
		if err != nil || publicFingerprint(existing) != digest {
			return nil, nil, reject("This publisher ID already uses another public key")
		}
		raw = nil // Do not rewrite a key already trusted in place.
	}
	return map[string]any{"id": src.ID, "url": base, "signers": []any{sig.Signer}, "fingerprint": digest, "official": false}, raw, nil
}

func (c catalogService) keyBytes(signer string) ([]byte, error) {
	if !signerPattern.MatchString(signer) {
		return nil, reject("Invalid module repository publisher")
	}
	keys, err := trustedDirectory(c.keys, c.owner)
	if errors.Is(err, unix.ENOENT) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer keys.Close()
	raw, err := readOwnedAt(keys, signer+".pem", c.owner, 8192)
	if errors.Is(err, unix.ENOENT) {
		return nil, nil
	}
	return raw, err
}

type sourceChange struct {
	AddDecision   string          `json:",omitempty"`
	AddSigner     string          `json:",omitempty"`
	Stage         *sourceAddStage `json:",omitempty"`
	KeyStage      *sourceAddStage `json:",omitempty"`
	AddedRow      string          `json:",omitempty"`
	AddID         string          `json:",omitempty"`
	Before, After string
	ID            string
	Add           bool
	Keys          map[string][]byte `json:",omitempty"` // Added keys; also supports legacy removal journals.
	Retired       map[string]string `json:",omitempty"` // SHA-256 of the exact key file bytes.
}

type sourcePlan struct {
	heldRemoval bool
	change      sourceChange
	after       []map[string]any
	public      map[string]any
}

func sourceState(src []map[string]any) string {
	raw, _ := json.Marshal(src)
	return sourceDigest(raw)
}

func sourceDigest(raw []byte) string {
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

func (c catalogService) planSource(ctx context.Context, action string, p map[string]any) (sourcePlan, error) {
	var out sourcePlan
	before, err := c.sources()
	if err != nil {
		return out, err
	}
	after := append([]map[string]any{}, before...)
	var selected map[string]any
	details := []string{}
	change := sourceChange{Before: sourceState(before), Add: action == "module.source-add", Keys: map[string][]byte{}, Retired: map[string]string{}}
	if change.Add {
		var raw []byte
		selected, raw, err = c.discover(ctx, text(p, "url"))
		if err != nil {
			return out, err
		}
		src := sourceSpecs([]map[string]any{selected})[0]
		if len(before) >= 16 {
			return out, reject("At most 16 module repositories are supported")
		}
		for _, s := range sourceSpecs(before) {
			if s.ID == src.ID || s.URL == src.URL {
				return out, reject("This module repository is already configured")
			}
		}
		if fp := p["keyFingerprint"]; fp != nil && fp != "" && fp != src.Fingerprint {
			return out, reject("Repository signing key changed. Review the repository again.")
		}
		details = []string{src.URL, "Publisher: " + strings.Join(src.Signers, ", ")}
		if src.Fingerprint != "" {
			enriched := map[string]any{}
			for k, v := range p {
				enriched[k] = v
			}
			enriched["keyFingerprint"] = src.Fingerprint
			p = enriched
			details = append(details, "SHA256: "+src.Fingerprint, "Trust this publisher to provide executable NAS modules")
		}
		if raw != nil {
			change.Keys[src.Signers[0]] = raw
		}
		after = append(after, selected)
	} else {
		for i, s := range before {
			if text(s, "id") == text(p, "target") {
				selected = s
				after = slices.Delete(after, i, i+1)
				break
			}
		}
		if selected == nil {
			return out, reject("Module repository not found")
		}
		details = []string{text(selected, "url"), "Installed modules are retained"}
		for _, signer := range sourceSpecs([]map[string]any{selected})[0].Signers {
			if strings.HasPrefix(signer, "panasms-") {
				continue
			}
			held, err := c.publisherFenced(signer)
			if err != nil {
				return out, err
			}
			if held {
				out.heldRemoval = true
				continue
			}
			if slices.ContainsFunc(sourceSpecs(after), func(s source) bool { return slices.Contains(s.Signers, signer) }) {
				continue
			}
			raw, err := c.keyBytes(signer)
			if err != nil {
				return out, err
			}
			if raw != nil {
				change.Retired[signer] = sourceDigest(raw)
			}
		}
	}
	change.ID, change.After = text(selected, "id"), sourceState(after)
	state := make([]any, len(before))
	for i, s := range before {
		state[i] = s
	}
	fp, err := systemops.Fingerprint(action, p, []any{state, selected})
	if err != nil {
		return out, err
	}
	return sourcePlan{heldRemoval: out.heldRemoval, change: change, after: after, public: map[string]any{"target": change.ID, "confirmation": change.ID, "details": details, "publisherFingerprint": selected["fingerprint"], "fingerprint": fp}}, nil
}

// Direct archive installs also use the key directory. Refuse to trust a
// key written by an interrupted source change until that change is resolved.
func (s store) checkSourceTrust() error {
	dir, err := trustedDirectory(s.root, s.owner)
	if err != nil {
		return err
	}
	defer dir.Close()
	var stat unix.Stat_t
	err = unix.Fstatat(int(dir.Fd()), sourceIntent, &stat, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	return reject("Review the interrupted module repository change before installing modules")
}

// Config replacement is the commit point. On restart, discard an uncommitted
// added key or finish retiring a removed key. Never touch installed receipts.
func (c catalogService) repairSources(ctx context.Context, dir *os.File, r *systemops.Reporter) error {
	if err := c.recoverSourceAddWrites(ctx, dir, r); err != nil {
		return err
	}
	if err := c.recoverPublisherClaim(ctx, dir, r); err != nil {
		return err
	}
	raw, err := readOwnedAt(dir, sourceIntent, c.owner, maxSourceState)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	lock, err := c.store.lock(ctx, r)
	if err != nil {
		return err
	}
	defer lock.Close()
	if repaired, _ := ctx.Value(sourceRepairKey{}).(*bool); repaired != nil {
		*repaired = true
	}
	err = c.finishSourceChange(dir, raw)
	if err == errSourceAddFenced {
		return nil
	}
	return err
}

func (c catalogService) finishSourceChange(dir *os.File, raw []byte) error {
	var change sourceChange
	if systemops.Decode(raw, &change) != nil || identifier(change.ID) != nil || change.Before == change.After ||
		len(change.Retired) > 0 && (change.Add || len(change.Keys) > 0) {
		return reject("Invalid module repository journal")
	}
	if change.AddID != "" {
		return c.finishSourceAdd(dir, change)
	}
	sources, err := c.sources()
	if err != nil {
		return err
	}
	state := sourceState(sources)
	committed := state == change.After
	drifted := !committed && state != change.Before
	if drifted && change.Add {
		return reject("Module repository configuration changed during recovery")
	}
	configured := sourceSpecs(sources)
	if drifted || change.Add != committed {
		retired := change.Retired
		if retired == nil {
			retired = map[string]string{}
		}
		for signer, key := range change.Keys {
			retired[signer] = sourceDigest(key)
		}
		for _, signer := range names(retired) {
			expected := retired[signer]
			if !archiveDigest.MatchString(expected) || !signerPattern.MatchString(signer) {
				return reject("Invalid module repository journal")
			}
			if strings.HasPrefix(signer, "panasms-") {
				return reject("Cannot retire a configured publisher")
			}
			if !change.Add && slices.ContainsFunc(configured, func(s source) bool { return slices.Contains(s.Signers, signer) }) {
				if drifted {
					continue
				}
				return reject("Cannot retire a configured publisher")
			}
			if drifted {
				// A later save makes the removal ambiguous. Preserve the
				// public key and fence this unconfigured signer for review.
				if err := c.holdFailedAdd(dir, signer); err != nil {
					return err
				}
				continue
			}
			current, err := c.keyBytes(signer)
			if err != nil {
				return err
			}
			if current == nil {
				continue
			}
			if expected != sourceDigest(current) {
				return reject("Module repository key changed during recovery")
			}
			keys, err := trustedDirectory(c.keys, c.owner)
			if err != nil {
				return err
			}
			err = unlinkCatalogFile(keys, signer+".pem")
			keys.Close()
			if err != nil {
				return err
			}
		}
	}
	if !change.Add && (committed || drifted && !slices.ContainsFunc(configured, func(s source) bool { return s.ID == change.ID })) {
		if err = unlinkCatalogFile(dir, catalogCacheName(change.ID)); err != nil {
			return err
		}
	}
	return unlinkCatalogFile(dir, sourceIntent)
}

// applySource distinguishes a pre-commit failure from post-commit cleanup.
func (c catalogService) applySource(dir *os.File, plan sourcePlan) (cleanupErr, err error) {
	change := plan.change
	// Removing an inactive row has no publisher key to retire. Invalidate
	// its cache before replacing the config so later edits need no replay.
	journal := !plan.heldRemoval || len(change.Retired) != 0
	if change.Add {
		row := plan.after[len(plan.after)-1]
		src := sourceSpecs([]map[string]any{row})[0]
		journal = len(change.Keys) != 0
		if !journal && src.Fingerprint != "" && len(src.Signers) == 1 {
			var err error
			journal, err = c.publisherFenced(src.Signers[0])
			if err != nil {
				return nil, err
			}
		}
		if journal {
			change.AddedRow = sourceTrustState(src)
			change.AddSigner = src.Signers[0]
		}
	}
	next, err := json.Marshal(plan.after)
	if err != nil {
		return nil, err
	}
	if len(next) > maxSourceState {
		return nil, systemops.BeforeMutation(reject("Module repository state is too large"))
	}
	config, err := trustedDirectory(filepath.Dir(c.config), c.owner)
	if err != nil {
		return nil, err
	}
	defer config.Close()
	if change.AddSigner != "" {
		// An early I/O failure can leave no journal to recover. Keep new or
		// already-held publishers inactive until their enrollment completes.
		if err := c.claimPublisher(dir, &change); err != nil {
			return nil, err
		}
		stage, err := c.prepareSourceAdd(config, change.AddID, next, func(pending sourceAddStage) error {
			change.Stage = &pending
			return c.recordSourceAddDecision(dir, &change, "preparing")
		})
		if err != nil {
			return nil, err
		}
		change.Stage = &stage
		change.AddDecision = ""
	}
	raw, err := json.Marshal(change)
	if err == nil && len(raw) > maxSourceState {
		err = reject("Module repository state is too large")
		if change.Stage == nil {
			err = systemops.BeforeMutation(err)
		}
	}
	if err != nil {
		if change.Stage != nil {
			err = errors.Join(err, change.Stage.cleanup(config))
		}
		return nil, err
	}
	if journal {
		if change.AddID != "" {
			err = c.writeSourceAddRecord(dir, sourceIntent, raw, false)
		} else {
			err = atomicAt(dir, sourceIntent, raw, 0600, c.owner)
		}
		if err != nil {
			// Sync may have failed after rename. Preserve the private stage if
			// the journal can be observed and recovered on a subsequent run.
			if change.Stage != nil {
				var stat unix.Stat_t
				if errors.Is(unix.Fstatat(int(dir.Fd()), sourceIntent, &stat, unix.AT_SYMLINK_NOFOLLOW), unix.ENOENT) {
					err = errors.Join(err, change.Stage.cleanup(config))
				}
			}
			return nil, err
		}
	}
	boundary := func(stage string) error {
		if c.sourceBoundary != nil {
			return c.sourceBoundary(stage)
		}
		return nil
	}
	if change.Add || !journal {
		if err = unlinkCatalogFile(dir, catalogCacheName(change.ID)); err != nil {
			return nil, err
		}
	}
	if change.Add {
		if err = boundary("key-written"); err != nil {
			return nil, err
		}
	}
	if change.Stage != nil {
		renamed, err := change.Stage.publish(config, filepath.Base(c.config))
		if err != nil {
			if renamed {
				return err, nil
			}
			return nil, err
		}
	} else if err := atomicAt(config, filepath.Base(c.config), next, 0600, c.owner); err != nil {
		return nil, err
	}
	if err = boundary("config-written"); err != nil {
		return err, nil
	}
	if !journal {
		return nil, nil
	}
	if change.Add {
		return c.finishSourceAdd(dir, change), nil
	}
	return c.finishSourceChange(dir, raw), nil
}
