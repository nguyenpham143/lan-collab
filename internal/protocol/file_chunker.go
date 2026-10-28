package protocol

import (
	"errors"
	"fmt"
	"strings"
	"sync"
)

// MaxFileSize bounds one trasnfer
const MaxFileSize int64 = 64 << 20 //64 MiB

// FileInitMeta is the JSON payload of FILE_INIT (seq_num = 0)
type FileInitMeta struct {
	Filename    string `json:"filename"`
	Size        int64  `json:"size"`
	TotalChunks uint32 `json:"total_chunks"`
	SHA256      string `json:"sha256"`
}

// Reassembly errors
var (
	ErrUnknownTransfer = errors.New("protocol: chunk for a transfer without FILE_INIT")
	ErrBadFileMeta     = errors.New("protocol: invalid FILE_INIT metadata")
	ErrChunkOutOfRange = errors.New("protocol: chunk sequence number out of range")
	ErrChunkTooLarge   = errors.New("protocol: chunk larger than 1024 bytes")
	ErrSizeMismatch    = errors.New("protocol: reassembled size does not match FILE_INIT")
	ErrHashMismatch    = errors.New("protocol: SHA-256 of reassembled file does not match FILE_INIT")
)

// ExpectedChunks returns how many chunks a file of the given size is split into
func ExpectedChunks(size int64) uint32 {
	if size <= 0 {
		return 1
	}
	return uint32((size + MaxChunkSize - 1) / MaxChunkSize)
}

// checkShape validates the numeric fields that reassembly depends on.
func (m FileInitMeta) checkShape() error {
	if m.Size < 0 || m.Size > MaxFileSize {
		return fmt.Errorf("%w: size %d outside 0..%d", ErrBadFileMeta, m.Size, MaxFileSize)
	}
	if m.TotalChunks != ExpectedChunks(m.Size) {
		return fmt.Errorf("%w: %d chunks announced for %d bytes", ErrBadFileMeta, m.TotalChunks, m.Size)
	}
	if len(m.SHA256) != 64 {
		return fmt.Errorf("%w: sha256 must be 64 hex characters", ErrBadFileMeta)
	}
	return nil
}

// Validate checks all metadata fields, including the filename. Receivers call it before accepting a FILE_INIT
func (m FileInitMeta) Validate() error {
	if err := m.checkShape(); err != nil {
		return err
	}
	if m.Filename == "" || len(m.Filename) > 255 {
		return fmt.Errorf("%w: filename must be 1..255 bytes", ErrBadFileMeta)
	}
	return nil
}

// SplitFileChunks slices data into chunks of at most 1024 bytes and computes the metadata for FILE_INIT
func SplitFileChunks(data []byte) (meta FileInitMeta, chunks [][]byte) {
	meta.Size = int64(len(data))
	meta.SHA256 = SHA256Hex(data)
	if len(data) == 0 {
		meta.TotalChunks = 1
		return meta, [][]byte{{}}
	}
	chunks = make([][]byte, 0, ExpectedChunks(meta.Size))
	for off := 0; off < len(data); off += MaxChunkSize {
		end := off + MaxChunkSize
		if end > len(data) {
			end = len(data)
		}
		chunks = append(chunks, data[off:end])
	}
	meta.TotalChunks = uint32(len(chunks))
	return meta, chunks
}

type reasmKey struct {
	sender uint16
	stream uint16
}

type reasmState struct {
	meta     FileInitMeta
	chunks   map[uint32][]byte
	received int64
}

// FileReassembler reassembles file chunks from multiple FILE_CHUNK messages, keyed by (sender, stream).
type FileReassembler struct {
	mu     sync.Mutex
	states map[reasmKey]*reasmState
}

// NewFileReassembler returns an empty reassembler.
func NewFileReassembler() *FileReassembler {
	return &FileReassembler{states: make(map[reasmKey]*reasmState)}
}

// AddInit registers (or restarts) the transfer identified by (senderID, streamID).
func (r *FileReassembler) AddInit(senderID, streamID uint16, meta FileInitMeta) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.states[reasmKey{senderID, streamID}] = &reasmState{
		meta:   meta,
		chunks: make(map[uint32][]byte),
	}
}

// AddChunk adds a chunk to the reassembly state. Returns true if the file is complete.
func (r *FileReassembler) AddChunk(senderID, streamID uint16, seqNum uint32, data []byte) (completeData []byte, meta FileInitMeta, done bool, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	key := reasmKey{senderID, streamID}
	st, ok := r.states[key]
	if !ok {
		return nil, FileInitMeta{}, false, ErrUnknownTransfer
	}
	meta = st.meta
	if err := meta.checkShape(); err != nil {
		delete(r.states, key)
		return nil, meta, false, err
	}
	if seqNum == 0 || seqNum > meta.TotalChunks {
		return nil, meta, false, fmt.Errorf("%w: %d not in 1..%d", ErrChunkOutOfRange, seqNum, meta.TotalChunks)
	}
	if len(data) > MaxChunkSize {
		delete(r.states, key)
		return nil, meta, false, ErrChunkTooLarge
	}
	if _, dup := st.chunks[seqNum]; dup {
		return nil, meta, false, nil
	}
	st.received += int64(len(data))
	if st.received > meta.Size {
		delete(r.states, key)
		return nil, meta, false, ErrSizeMismatch
	}
	st.chunks[seqNum] = append([]byte(nil), data...)
	if uint32(len(st.chunks)) < meta.TotalChunks {
		return nil, meta, false, nil
	}

	delete(r.states, key)
	out := make([]byte, 0, st.received)
	for i := uint32(1); i <= meta.TotalChunks; i++ {
		out = append(out, st.chunks[i]...)
	}
	if int64(len(out)) != meta.Size {
		return nil, meta, false, ErrSizeMismatch
	}
	if SHA256Hex(out) != strings.ToLower(meta.SHA256) {
		return nil, meta, false, ErrHashMismatch
	}
	return out, meta, true, nil
}

// Pending reports whether a transfer is still being reassembled.
func (r *FileReassembler) Pending(senderID, streamID uint16) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.states[reasmKey{senderID, streamID}]
	return ok
}

// Abort forgets a transfer without completing it.
func (r *FileReassembler) Abort(senderID, streamID uint16) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.states, reasmKey{senderID, streamID})
}
