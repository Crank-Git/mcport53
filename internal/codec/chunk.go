package codec

// ChunkSize is the default maximum size (bytes) of each result chunk payload.
//
// It is sized so a chunked envelope (base64 payload, a 26-character session,
// a tool name of up to 63 characters, cursor and compression markers) marshals
// within MaxEnvelopeTXT, and so the whole response fits a 1232-byte EDNS0 UDP
// message with room for a 255-byte question name and a TSIG record.
const ChunkSize = 400

// ChunkPayload splits data into consecutive pieces of at most size bytes.
// An empty input yields no chunks.
func ChunkPayload(data []byte, size int) [][]byte {
	if size <= 0 {
		size = ChunkSize
	}
	if len(data) == 0 {
		return nil
	}
	var chunks [][]byte
	for len(data) > 0 {
		n := size
		if n > len(data) {
			n = len(data)
		}
		chunks = append(chunks, data[:n])
		data = data[n:]
	}
	return chunks
}

// Assemble concatenates decoded chunk payloads in order.
func Assemble(chunks [][]byte) []byte {
	total := 0
	for _, c := range chunks {
		total += len(c)
	}
	out := make([]byte, 0, total)
	for _, c := range chunks {
		out = append(out, c...)
	}
	return out
}
