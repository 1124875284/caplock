package mcp

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

func decodeResponse(data []byte, requestID int64) (json.RawMessage, error) {
	var response rpcResponse
	if err := json.Unmarshal(data, &response); err != nil {
		return nil, errors.New("server sent invalid JSON-RPC")
	}
	if response.Method != "" {
		if response.ID != nil && string(response.ID) != "null" {
			return nil, errors.New("server sent an unexpected JSON-RPC request during tool discovery")
		}
		return nil, nil
	}
	if response.JSONRPC != "2.0" {
		return nil, errors.New("server sent a non-JSON-RPC 2.0 response")
	}
	if !idMatches(response.ID, requestID) {
		return nil, nil
	}
	if response.Error != nil {
		return nil, fmt.Errorf("server returned JSON-RPC error %d", response.Error.Code)
	}
	if len(response.Result) == 0 {
		return nil, errors.New("server returned an empty JSON-RPC result")
	}
	return response.Result, nil
}

func idMatches(raw json.RawMessage, id int64) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte(fmt.Sprintf("%d", id)))
}
