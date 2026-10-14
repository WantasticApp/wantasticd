package wusp

import (
	"strconv"
	"strings"
)

type ControlResultState string

const (
	ControlResultPending ControlResultState = "pending"
	ControlResultSuccess ControlResultState = "success"
	ControlResultError   ControlResultState = "error"
)

const (
	ControlCodeOK                = "WUSP_OK"
	ControlCodeOperationAccepted = "WUSP_OPERATION_ACCEPTED"
	ControlCodeOperationPending  = "WUSP_OPERATION_PENDING"
	ControlCodeOperationSuccess  = "WUSP_OPERATION_SUCCEEDED"
	ControlCodeDeviceRejected    = "WUSP_DEVICE_REJECTED"
	ControlCodeInvalidRequest    = "WUSP_INVALID_REQUEST"
	ControlCodeUnsupported       = "WUSP_UNSUPPORTED"
	ControlCodeAgentTimeout      = "WUSP_AGENT_TIMEOUT"
	ControlCodeAgentError        = "WUSP_AGENT_ERROR"
	ControlCodeAckTimeout        = "WUSP_ACK_TIMEOUT"
	ControlCodeDeliveryUnknown   = "WUSP_DELIVERY_UNCONFIRMED"
	ControlCodePeerOffline       = "WUSP_PEER_OFFLINE"
	ControlCodeControllerTimeout = "WUSP_CONTROLLER_TIMEOUT"
	ControlCodeControllerError   = "WUSP_CONTROLLER_ERROR"
)

const (
	MetadataKeyResultState     = "wusp.result.state"
	MetadataKeyResultCode      = "wusp.result.code"
	MetadataKeyResultMessage   = "wusp.result.message"
	MetadataKeyResultRequestID = "wusp.result.request_id"
	MetadataKeyResultRetryable = "wusp.result.retryable"
)

type ControlResult struct {
	State     ControlResultState
	Code      string
	Message   string
	RequestID uint64
	Retryable bool
}

func WithControlResult(metadata map[string]string, result ControlResult) map[string]string {
	out := CloneMetadata(metadata)
	if out == nil {
		out = make(map[string]string, 5)
	}
	out[MetadataKeyResultState] = string(result.State)
	out[MetadataKeyResultCode] = strings.TrimSpace(result.Code)
	out[MetadataKeyResultMessage] = strings.TrimSpace(result.Message)
	out[MetadataKeyResultRequestID] = strconv.FormatUint(result.RequestID, 10)
	out[MetadataKeyResultRetryable] = strconv.FormatBool(result.Retryable)
	return out
}

func ControlResultFromMetadata(metadata map[string]string) (ControlResult, bool) {
	state := ControlResultState(strings.TrimSpace(metadata[MetadataKeyResultState]))
	if state != ControlResultPending && state != ControlResultSuccess && state != ControlResultError {
		return ControlResult{}, false
	}
	requestID, _ := strconv.ParseUint(strings.TrimSpace(metadata[MetadataKeyResultRequestID]), 10, 64)
	retryable, _ := strconv.ParseBool(strings.TrimSpace(metadata[MetadataKeyResultRetryable]))
	return ControlResult{State: state, Code: strings.TrimSpace(metadata[MetadataKeyResultCode]), Message: strings.TrimSpace(metadata[MetadataKeyResultMessage]), RequestID: requestID, Retryable: retryable}, true
}

func FinalizeAgentResponse(req USPAgentRequest, resp USPAgentResponse) USPAgentResponse {
	resp.ID = req.ID
	resp.Method = req.Method
	metadata := CloneMetadata(resp.Metadata)
	if sequence, ok := RequestSequence(req.Metadata); ok {
		metadata = WithResponseSequence(metadata, sequence)
	}
	if _, ok := ControlResultFromMetadata(metadata); ok {
		resp.Metadata = metadata
		return resp
	}
	resp.Metadata = WithControlResult(metadata, agentControlResult(req.ID, resp))
	return resp
}

func agentControlResult(requestID uint64, resp USPAgentResponse) ControlResult {
	if strings.TrimSpace(resp.Error) != "" {
		return classifyAgentError(requestID, resp.Method, resp.Error)
	}
	status, message := operationStatus(resp.Message)
	switch strings.ToLower(status) {
	case "pending":
		return ControlResult{State: ControlResultPending, Code: ControlCodeOperationAccepted, Message: message, RequestID: requestID}
	case "error":
		return ControlResult{State: ControlResultError, Code: ControlCodeDeviceRejected, Message: message, RequestID: requestID}
	case "success":
		return ControlResult{State: ControlResultSuccess, Code: ControlCodeOperationSuccess, Message: message, RequestID: requestID}
	default:
		return ControlResult{State: ControlResultSuccess, Code: ControlCodeOK, RequestID: requestID}
	}
}

func classifyAgentError(requestID uint64, method USPAgentMethod, message string) ControlResult {
	lower := strings.ToLower(strings.TrimSpace(message))
	result := ControlResult{State: ControlResultError, Code: ControlCodeAgentError, Message: strings.TrimSpace(message), RequestID: requestID}
	switch {
	case strings.Contains(lower, "deadline exceeded"), strings.Contains(lower, "timed out"), strings.Contains(lower, "timeout"):
		result.Code = ControlCodeAgentTimeout
		result.Retryable = true
		if ShouldQueueUSPRequest(USPAgentRequest{Method: method}) {
			result.State = ControlResultPending
		}
	case strings.Contains(lower, "unsupported"):
		result.Code = ControlCodeUnsupported
	case strings.Contains(lower, "invalid"), strings.Contains(lower, "missing"), strings.Contains(lower, "required"):
		result.Code = ControlCodeInvalidRequest
	}
	return result
}

func operationStatus(msg *Message) (status, detail string) {
	if msg == nil {
		return "", ""
	}
	for _, field := range msg.Fields {
		path := strings.TrimSpace(field.Path)
		switch {
		case strings.HasSuffix(path, ".LastOperationStatus") || strings.HasSuffix(path, ".LastCommandStatus"):
			status = strings.TrimSpace(ValueToString(field.Val))
		case strings.HasSuffix(path, ".LastOperationMessage") || strings.HasSuffix(path, ".LastCommandOutput"):
			detail = strings.TrimSpace(ValueToString(field.Val))
		}
	}
	return status, detail
}
