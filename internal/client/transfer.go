package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"lancollab/internal/protocol"
)

func (c *Controller) runUpload(s *session, key string, target, stream uint16, initBody []byte, chunks [][]byte) {
	send := func(msgType uint8, seq uint32, flags uint8, body []byte) error {
		return s.ep.SendReliable(protocol.ServerID, s.serverUDP, s.key, protocol.UDPHeader{
			MsgType:  msgType,
			Flags:    flags,
			StreamID: stream,
			SenderID: s.userID,
			TargetID: target,
			SeqNum:   seq,
		}, body)
	}
	fail := func(err error) {
		c.updateTransfer(key, true, func(tp *TransferProgress) {
			tp.Stage = StageFailed
			tp.Error = err.Error()
		})
	}
	// proceed reports whether to keep uploading; it stops once the transfer failed or the receiver left.
	proceed := func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		tp := c.transfers[key]
		if tp == nil || tp.Stage == StageFailed {
			return false
		}
		if !c.peerOnlineLocked(target) {
			tp.Stage = StageFailed
			tp.Error = "the recipient went offline"
			cp := *tp
			c.emitLocked(ClientEvent{Kind: EventFileProgress, Progress: &cp})
			return false
		}
		return true
	}

	if !proceed() {
		return
	}
	if err := send(protocol.MsgFileInit, 0, 0, initBody); err != nil {
		fail(err)
		return
	}
	var sent int64
	for i, chunk := range chunks {
		if !proceed() {
			return
		}
		if err := send(protocol.MsgFileChunk, uint32(i+1), 0, chunk); err != nil {
			fail(err)
			return
		}
		sent += int64(len(chunk))
		c.updateTransfer(key, false, func(tp *TransferProgress) {
			if tp.Stage == StageSending {
				tp.Transferred = sent
				tp.Percent = percent(sent, tp.Total)
			}
		})
	}
	if !proceed() {
		return
	}
	if err := send(protocol.MsgFileEnd, uint32(len(chunks)+1), protocol.FlagEOM, nil); err != nil {
		fail(err)
		return
	}
	c.updateTransfer(key, true, func(tp *TransferProgress) {
		if tp.Stage == StageSending {
			tp.Stage = StageAwaitingConfirm
			tp.Transferred, tp.Percent = tp.Total, 100
		}
	})
}

func (c *Controller) onFileInit(s *session, h protocol.UDPHeader, plaintext []byte) {
	var meta protocol.FileInitMeta
	if err := json.Unmarshal(plaintext, &meta); err != nil {
		return
	}
	meta.Filename = sanitizeFilename(meta.Filename)
	key := transferKey(DirectionRecv, h.SenderID, h.StreamID)
	tp := &TransferProgress{
		StreamID: h.StreamID, PeerID: h.SenderID, Filename: meta.Filename,
		Direction: DirectionRecv, Total: meta.Size, Stage: StageReceiving,
	}
	err := meta.Validate()
	c.mu.Lock()
	tp.PeerName = c.peerNameLocked(h.SenderID)
	// PEER_UPDATE (TCP) may beat this FILE_INIT (UDP); if the sender already left, fail the transfer now.
	senderGone := err == nil && !c.peerOnlineLocked(h.SenderID)
	if senderGone {
		name := tp.PeerName
		if name == "" {
			name = "user #" + strconv.Itoa(int(h.SenderID))
		}
		tp.Stage, tp.Error = StageFailed, name+" went offline before the transfer started"
	} else if err != nil {
		tp.Stage, tp.Error = StageFailed, err.Error()
	} else {
		s.reasm.AddInit(h.SenderID, h.StreamID, meta)
	}
	c.putTransferLocked(key, tp)
	c.mu.Unlock()
	if err != nil {
		c.sendFileDone(s, h.SenderID, h.StreamID, false, err.Error())
	}
}

func (c *Controller) onFileChunk(s *session, h protocol.UDPHeader, plaintext []byte) {
	key := transferKey(DirectionRecv, h.SenderID, h.StreamID)
	data, meta, done, err := s.reasm.AddChunk(h.SenderID, h.StreamID, h.SeqNum, plaintext)
	if err != nil {
		if errors.Is(err, protocol.ErrUnknownTransfer) {
			return // transfer already failed or finished
		}
		c.updateTransfer(key, true, func(tp *TransferProgress) {
			tp.Stage = StageFailed
			tp.Error = err.Error()
		})
		c.sendFileDone(s, h.SenderID, h.StreamID, false, err.Error())
		return
	}
	if !done {
		n := int64(len(plaintext))
		c.updateTransfer(key, false, func(tp *TransferProgress) {
			tp.Transferred += n
			tp.Percent = percent(tp.Transferred, tp.Total)
			c.recvActivity[key] = time.Now() // updateTransfer holds c.mu
		})
		return
	}
	// SHA-256 matched inside the reassembler: the file is intact.
	c.mu.Lock()
	dir := c.downloadDir
	c.mu.Unlock()
	saved, saveErr := saveDownload(dir, meta.Filename, data)
	c.updateTransfer(key, true, func(tp *TransferProgress) {
		tp.Transferred, tp.Percent = tp.Total, 100
		tp.Verified = true
		tp.Stage = StageVerified
		if saveErr != nil {
			tp.Error = "verified, but saving failed: " + saveErr.Error()
		} else {
			tp.SavedPath = saved
		}
	})
	c.sendFileDone(s, h.SenderID, h.StreamID, true, "")
}

// onFileEnd checks the file is complete; delivery is in order, so any missing chunk means data was lost.
func (c *Controller) onFileEnd(s *session, h protocol.UDPHeader) {
	if !s.reasm.Pending(h.SenderID, h.StreamID) {
		return
	}
	s.reasm.Abort(h.SenderID, h.StreamID)
	reason := "FILE_END arrived before all chunks"
	c.updateTransfer(transferKey(DirectionRecv, h.SenderID, h.StreamID), true, func(tp *TransferProgress) {
		tp.Stage = StageFailed
		tp.Error = reason
	})
	c.sendFileDone(s, h.SenderID, h.StreamID, false, reason)
}

func (c *Controller) sendFileDone(s *session, to, stream uint16, ok bool, reason string) {
	body, err := protocol.MarshalJSONCompact(protocol.FileDonePayload{StreamID: stream, OK: ok, Reason: reason})
	if err != nil {
		return
	}
	_ = c.sendOnChatStream(s, protocol.MsgFileDone, to, body)
}

func (s *session) allocStream() uint16 {
	s.streamMu.Lock()
	defer s.streamMu.Unlock()
	id := s.nextStream
	s.nextStream++
	if s.nextStream < protocol.FirstFileStream { // wrapped around
		s.nextStream = protocol.FirstFileStream
	}
	return id
}

// expireIdleTransfers fails incoming transfers idle longer than the timeout, discards them and tells the sender.
func (c *Controller) expireIdleTransfers(s *session) {
	now := time.Now()
	var expired []TransferProgress
	c.mu.Lock()
	limit := c.idleTimeout
	if c.sess != s || limit <= 0 {
		c.mu.Unlock()
		return
	}
	for key, last := range c.recvActivity {
		tp := c.transfers[key]
		if tp == nil || tp.Stage != StageReceiving {
			delete(c.recvActivity, key)
			continue
		}
		if now.Sub(last) < limit {
			continue
		}
		delete(c.recvActivity, key)
		tp.Stage = StageFailed
		tp.Error = fmt.Sprintf("no data received for %v", limit.Round(time.Second))
		cp := *tp
		c.emitLocked(ClientEvent{Kind: EventFileProgress, Progress: &cp})
		expired = append(expired, cp)
	}
	c.mu.Unlock()

	for _, tp := range expired {
		s.reasm.Abort(tp.PeerID, tp.StreamID)
		// Tell the sender in the background; this may wait for the send window and must not block the stats loop.
		go c.sendFileDone(s, tp.PeerID, tp.StreamID, false, tp.Error)
	}
}

// transferUnfinished reports whether a transfer in this stage can still fail.
func transferUnfinished(stage string) bool {
	return stage == StageSending || stage == StageReceiving || stage == StageAwaitingConfirm
}

// failOfflineTransfersLocked fails unfinished transfers whose peer went offline and returns them; c.mu must be held.
func (c *Controller) failOfflineTransfersLocked() []TransferProgress {
	var failed []TransferProgress
	for _, key := range c.transferOrder {
		tp := c.transfers[key]
		if tp == nil || !transferUnfinished(tp.Stage) || c.peerOnlineLocked(tp.PeerID) {
			continue
		}
		name := tp.PeerName
		if name == "" {
			name = "user #" + strconv.Itoa(int(tp.PeerID))
		}
		tp.Stage = StageFailed
		tp.Error = name + " went offline"
		cp := *tp
		c.emitLocked(ClientEvent{Kind: EventFileProgress, Progress: &cp})
		failed = append(failed, cp)
	}
	return failed
}

// putTransferLocked records a new transfer and publishes it. c.mu must be held.
func (c *Controller) putTransferLocked(key string, tp *TransferProgress) {
	if tp.StartedAt == 0 {
		tp.StartedAt = time.Now().UnixMilli()
	}
	if _, exists := c.transfers[key]; !exists {
		c.transferOrder = append(c.transferOrder, key)
	}
	c.transfers[key] = tp
	if tp.Direction == DirectionRecv && tp.Stage == StageReceiving {
		c.recvActivity[key] = time.Now()
	}
	c.pruneTransfersLocked()
	c.lastEmit[key] = time.Now()
	cp := *tp
	c.emitLocked(ClientEvent{Kind: EventFileProgress, Progress: &cp})
}

// updateTransfer applies fn and publishes the result; progress-only updates (force=false) are rate-limited.
func (c *Controller) updateTransfer(key string, force bool, fn func(tp *TransferProgress)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	tp := c.transfers[key]
	if tp == nil {
		return
	}
	fn(tp)
	now := time.Now()
	if !force && now.Sub(c.lastEmit[key]) < progressEmitInterval {
		return
	}
	c.lastEmit[key] = now
	cp := *tp
	c.emitLocked(ClientEvent{Kind: EventFileProgress, Progress: &cp})
}

// pruneTransfersLocked keeps at most transferLimit entries by dropping the oldest finished ones.
func (c *Controller) pruneTransfersLocked() {
	for len(c.transferOrder) > transferLimit {
		removed := false
		for i, key := range c.transferOrder {
			tp := c.transfers[key]
			if tp == nil || tp.Stage == StageVerified || tp.Stage == StageFailed {
				c.transferOrder = append(c.transferOrder[:i], c.transferOrder[i+1:]...)
				delete(c.transfers, key)
				delete(c.lastEmit, key)
				delete(c.recvActivity, key)
				removed = true
				break
			}
		}
		if !removed {
			return
		}
	}
}

func transferKey(direction string, peer, stream uint16) string {
	return direction + ":" + strconv.Itoa(int(peer)) + ":" + strconv.Itoa(int(stream))
}

func percent(done, total int64) int {
	if total <= 0 {
		return 100
	}
	p := int(done * 100 / total)
	if p > 100 {
		p = 100
	}
	return p
}

// sanitizeFilename keeps the base name and strips unsafe characters, so a sender can never write outside downloads/.
func sanitizeFilename(name string) string {
	name = path.Base(strings.ReplaceAll(name, "\\", "/"))
	name = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || strings.ContainsRune(`<>:"/\|?*`, r) || !unicode.IsPrint(r) {
			return '_'
		}
		return r
	}, name)
	name = strings.Trim(name, " .")
	if utf8.RuneCountInString(name) > 128 {
		runes := []rune(name)
		name = string(runes[:128])
	}
	if name == "" || name == "." || name == ".." {
		name = "file.bin"
	}
	return name
}

// saveDownload writes into dir without overwriting: "a.txt" becomes "a (1).txt", "a (2).txt", ...
func saveDownload(dir, name string, data []byte) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	ext := filepath.Ext(name)
	stem := strings.TrimSuffix(name, ext)
	for i := 0; i < 1000; i++ {
		candidate := name
		if i > 0 {
			candidate = fmt.Sprintf("%s (%d)%s", stem, i, ext)
		}
		full := filepath.Join(dir, candidate)
		f, err := os.OpenFile(full, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		if err != nil {
			return "", err
		}
		if _, err := f.Write(data); err != nil {
			f.Close()
			return "", err
		}
		if err := f.Close(); err != nil {
			return "", err
		}
		return full, nil
	}
	return "", errors.New("too many files with the same name")
}
