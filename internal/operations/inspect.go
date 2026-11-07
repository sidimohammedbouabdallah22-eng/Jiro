package operations

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/sidimohammedbouabdallah22-eng/Jiro/internal/accounts"
	"github.com/sidimohammedbouabdallah22-eng/Jiro/internal/adminaudit"
	"github.com/sidimohammedbouabdallah22-eng/Jiro/internal/gateway"
	_ "modernc.org/sqlite"
)

type dbRead struct {
	db   *sql.DB
	tx   *sql.Tx
	info Database
}

func (d *dbRead) close() {
	if d != nil {
		d.tx.Rollback()
		d.db.Close()
	}
}
func readOnlyDSN(path string) string {
	p := filepath.ToSlash(path)
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	u := url.URL{Scheme: "file", Path: p}
	q := url.Values{"mode": []string{"ro"}, "cache": []string{"private"}}
	u.RawQuery = q.Encode()
	return u.String()
}
func cleanSidecars(path string) error {
	for _, suffix := range []string{"-journal", "-wal", "-shm"} {
		info, err := os.Lstat(path + suffix)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Size() != 0 {
			return fmt.Errorf("%s has a nonempty/unsafe sidecar; recover and cleanly stop it before backup", path)
		}
	}
	return nil
}
func openRead(ctx context.Context, path, kind string) (*dbRead, error) {
	if err := regular(path, 1<<30); err != nil {
		return nil, err
	}
	if err := cleanSidecars(path); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", readOnlyDSN(path))
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	good := false
	defer func() {
		if !good {
			db.Close()
		}
	}()
	if _, err = db.ExecContext(ctx, "PRAGMA busy_timeout=100"); err != nil {
		return nil, err
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer func() {
		if !good {
			tx.Rollback()
		}
	}()
	// Reading schema establishes the SQLite shared lock for the entire copy.
	var tables int
	if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master").Scan(&tables); err != nil {
		return nil, err
	}
	var mode, check string
	var pagesize, version, appID int
	if err = tx.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&mode); err != nil {
		return nil, err
	}
	if mode != "delete" {
		return nil, errors.New("offline recovery currently supports clean DELETE-journal databases only")
	}
	if err = tx.QueryRowContext(ctx, "PRAGMA page_size").Scan(&pagesize); err != nil {
		return nil, err
	}
	if pagesize != 4096 {
		return nil, errors.New("unsupported database page size")
	}
	if err = tx.QueryRowContext(ctx, "PRAGMA quick_check").Scan(&check); err != nil || check != "ok" {
		return nil, fmt.Errorf("database integrity check failed: %v", err)
	}
	if err = tx.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return nil, err
	}
	if err = tx.QueryRowContext(ctx, "PRAGMA application_id").Scan(&appID); err != nil {
		return nil, err
	}
	result := &dbRead{db: db, tx: tx, info: Database{Schema: version}}
	if kind == "events" {
		if version < 1 || version > 2 || appID != 0 {
			return nil, errors.New("unsupported sender database schema/identity")
		}
		if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM events WHERE length(data)>16384 OR length(id)>128 OR length(path)>2048 OR length(ip)>64 OR length(action)>32").Scan(&tables); err != nil || tables != 0 {
			return nil, errors.New("sender records violate supported bounds")
		}
		result.info.Rows, result.info.Digest, err = digestQuery(ctx, tx, "SELECT seq,id,time_ns,action,ip,path,size,data FROM events ORDER BY seq", 100000)
		if err != nil {
			return nil, err
		}
		if version == 2 {
			if err = tx.QueryRowContext(ctx, "SELECT records,occurrences,enqueued,enqueued_occurrences,acked,acked_occurrences FROM event_totals WHERE singleton=1").Scan(&result.info.Records, &result.info.Occurrences, &result.info.Enqueued, &result.info.EnqueuedOccurrences, &result.info.Acked, &result.info.AckedOccurrences); err != nil {
				return nil, err
			}
			if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM export_outbox WHERE length(data)>16384 OR length(id)>128 OR occurrences<1").Scan(&tables); err != nil || tables != 0 {
				return nil, errors.New("outbox records violate supported bounds")
			}
			result.info.OutboxRows, result.info.OutboxDigest, err = digestQuery(ctx, tx, "SELECT seq,id,occurrences,size,data FROM export_outbox ORDER BY seq", 100000)
			if err != nil {
				return nil, err
			}
			err = tx.QueryRowContext(ctx, "SELECT destination,source_id FROM export_settings WHERE singleton=1").Scan(&result.info.Destination, &result.info.Source)
			if err != nil && !errors.Is(err, sql.ErrNoRows) {
				return nil, err
			}
			var occurrences uint64
			if err = tx.QueryRowContext(ctx, "SELECT coalesce(sum(occurrences),0) FROM export_outbox").Scan(&occurrences); err != nil {
				return nil, err
			}
			i := result.info
			if i.Acked > i.Enqueued || i.AckedOccurrences > i.EnqueuedOccurrences || i.Enqueued > i.Records || i.EnqueuedOccurrences > i.Occurrences || uint64(i.OutboxRows) != i.Enqueued-i.Acked || occurrences != i.EnqueuedOccurrences-i.AckedOccurrences {
				return nil, errors.New("sender export accounting is inconsistent")
			}
			if i.Destination != "" {
				source, e := hex.DecodeString(i.Source)
				u, e2 := url.Parse(i.Destination)
				if e != nil || len(source) != 16 || len(i.Destination) > 2048 || e2 != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
					return nil, errors.New("invalid persisted export identity/destination")
				}
			} else if i.OutboxRows != 0 || i.Source != "" {
				return nil, errors.New("outbox has no export destination")
			}
		}
	} else {
		if version != 1 || appID != 0x4f574543 {
			return nil, errors.New("unsupported reference collector schema/identity")
		}
		if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM collected_events WHERE length(data)>16384 OR length(id)>128 OR length(source_id)!=32 OR occurrences<1").Scan(&tables); err != nil || tables != 0 {
			return nil, errors.New("collector records violate supported bounds")
		}
		result.info.Rows, result.info.Digest, err = digestQuery(ctx, tx, "SELECT source_id,id,sequence,occurrences,data,digest FROM collected_events ORDER BY source_id,id", 2000000)
		if err != nil {
			return nil, err
		}
		if err = tx.QueryRowContext(ctx, "SELECT records,occurrences FROM collector_totals WHERE singleton=1").Scan(&result.info.Records, &result.info.Occurrences); err != nil {
			return nil, err
		}
		var count, occ uint64
		if err = tx.QueryRowContext(ctx, "SELECT count(*),coalesce(sum(occurrences),0) FROM collected_events").Scan(&count, &occ); err != nil {
			return nil, err
		}
		if count != result.info.Records || occ != result.info.Occurrences {
			return nil, errors.New("collector totals do not match receipts")
		}
	}
	if err = cleanSidecars(path); err != nil {
		return nil, err
	}
	good = true
	return result, nil
}
func digestQuery(ctx context.Context, tx *sql.Tx, query string, limit int64) (int64, string, error) {
	rows, err := tx.QueryContext(ctx, query)
	if err != nil {
		return 0, "", err
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return 0, "", err
	}
	h := sha256.New()
	var count int64
	for rows.Next() {
		count++
		if count > limit {
			return 0, "", errors.New("database exceeds supported record count")
		}
		values := make([]any, len(cols))
		pointers := make([]any, len(cols))
		for i := range values {
			pointers[i] = &values[i]
		}
		if err = rows.Scan(pointers...); err != nil {
			return 0, "", err
		}
		var raw []byte
		var id, digest string
		var occurrences int64
		for i, column := range cols {
			switch column {
			case "data":
				switch value := values[i].(type) {
				case []byte:
					raw = value
				case string:
					raw = []byte(value)
				}
			case "id":
				id, _ = values[i].(string)
			case "digest":
				digest, _ = values[i].(string)
			case "occurrences":
				occurrences, _ = values[i].(int64)
			}
		}
		var metadata struct {
			ID          string `json:"id"`
			Occurrences uint64 `json:"occurrences"`
		}
		if id == "" || len(raw) > 16384 || json.Unmarshal(raw, &metadata) != nil || metadata.ID != id || (occurrences > 0 && metadata.Occurrences != 0 && metadata.Occurrences != uint64(occurrences)) {
			return 0, "", errors.New("stored event JSON identity/count is invalid")
		}
		var decoded gateway.Event
		if err = json.Unmarshal(raw, &decoded); err != nil {
			return 0, "", fmt.Errorf("stored event cannot be decoded by the supported model: %w", err)
		}
		if digest != "" {
			receipt := sha256.New()
			receipt.Write(raw)
			fmt.Fprintf(receipt, "\x00%d", occurrences)
			if hex.EncodeToString(receipt.Sum(nil)) != digest {
				return 0, "", errors.New("collector receipt payload digest is invalid")
			}
		}
		data, e := json.Marshal(values)
		if e != nil {
			return 0, "", e
		}
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(data)))
		h.Write(size[:])
		h.Write(data)
	}
	return count, hex.EncodeToString(h.Sum(nil)), rows.Err()
}

func inspectHeld(ctx context.Context, p Paths, compileHistory bool) (State, []*dbRead, error) {
	var state State
	var readers []*dbRead
	fail := func(err error) (State, []*dbRead, error) {
		for _, r := range readers {
			r.close()
		}
		return state, nil, err
	}
	policy, err := gateway.CheckStateContext(ctx, p.Policy, compileHistory)
	if err != nil {
		return fail(err)
	}
	state.Policy = policy
	state.PolicyDigest, _, err = hashFile(ctx, p.Policy)
	if err != nil {
		return fail(err)
	}
	history, err := historyFiles(p.Policy)
	if err != nil {
		return fail(err)
	}
	h := sha256.New()
	for _, name := range history {
		sum, _, e := hashFile(ctx, name)
		if e != nil {
			return fail(e)
		}
		fmt.Fprintf(h, "%s\x00%s\n", filepath.Base(name), sum)
	}
	state.HistoryDigest = hex.EncodeToString(h.Sum(nil))
	if p.Events != "" {
		r, e := openRead(ctx, p.Events, "events")
		if e != nil {
			return fail(e)
		}
		readers = append(readers, r)
		state.Events = &r.info
	}
	if p.Collector != "" {
		r, e := openRead(ctx, p.Collector, "collector")
		if e != nil {
			return fail(e)
		}
		readers = append(readers, r)
		state.Collector = &r.info
		if len(readers) < 2 || state.Events.Source == "" {
			return fail(errors.New("a coordinated collector backup requires its export-bound sender"))
		}
		if e = coordinated(ctx, readers[0], r); e != nil {
			return fail(e)
		}
	}
	if p.Audit != "" {
		meta, e := adminaudit.Inspect(p.Audit)
		if e != nil {
			return fail(e)
		}
		state.Audit = &meta
	}
	if p.Accounts != "" {
		meta, e := accounts.Inspect(p.Accounts)
		if e != nil {
			return fail(e)
		}
		store, e := accounts.Open(p.Accounts)
		if e != nil {
			return fail(e)
		}
		data, e := os.ReadFile(p.Policy)
		if e != nil {
			return fail(e)
		}
		var config gateway.Config
		if e = json.Unmarshal(data, &config); e != nil {
			return fail(e)
		}
		ids := []string{}
		for _, app := range config.ApplicationList() {
			ids = append(ids, app.ApplicationID)
		}
		if e = store.CheckApplications(config.SchemaVersion, ids); e != nil {
			return fail(e)
		}
		state.Accounts = &meta
	}
	return state, readers, nil
}
func Inspect(ctx context.Context, p Paths, compileHistory bool) (State, error) {
	p, err := normalized(p)
	if err != nil {
		return State{}, err
	}
	release, err := acquire(p)
	if err != nil {
		return State{}, err
	}
	defer release()
	state, readers, err := inspectHeld(ctx, p, compileHistory)
	for _, r := range readers {
		r.close()
	}
	return state, err
}
func historyFiles(policy string) ([]string, error) {
	directory := policy + ".history"
	f, err := os.Open(directory)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	entries, err := f.ReadDir(1001)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if len(entries) > 1000 {
		return nil, errors.New("too many history files")
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, filepath.Join(directory, e.Name()))
	}
	sort.Strings(names)
	return names, nil
}
func coordinated(ctx context.Context, sender, receiver *dbRead) error {
	source := sender.info.Source
	var foreign int
	if err := receiver.tx.QueryRowContext(ctx, "SELECT count(*) FROM collected_events WHERE source_id<>?", source).Scan(&foreign); err != nil {
		return err
	}
	if foreign != 0 {
		return errors.New("collector is shared with other senders; coordinated rollback requires all senders, use external-collector scope")
	}
	rows, err := sender.tx.QueryContext(ctx, "SELECT id,occurrences,data FROM export_outbox ORDER BY seq")
	if err != nil {
		return err
	}
	defer rows.Close()
	var matched, occurrences uint64
	for rows.Next() {
		var id string
		var count uint64
		var data []byte
		if err = rows.Scan(&id, &count, &data); err != nil {
			return err
		}
		var remote []byte
		var remoteCount uint64
		err = receiver.tx.QueryRowContext(ctx, "SELECT data,occurrences FROM collected_events WHERE source_id=? AND id=?", source, id).Scan(&remote, &remoteCount)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return err
		}
		canonical, e := json.Marshal(json.RawMessage(data))
		if e != nil {
			return e
		}
		if string(canonical) != string(remote) || count != remoteCount {
			return errors.New("collector receipt differs from pending sender event")
		}
		matched++
		occurrences += count
	}
	if err = rows.Err(); err != nil {
		return err
	}
	if receiver.info.Records != sender.info.Acked+matched || receiver.info.Occurrences != sender.info.AckedOccurrences+occurrences {
		return errors.New("sender and collector checkpoints do not reconcile; refusing a potentially lossy recovery set")
	}
	return nil
}
