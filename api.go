package fw

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/advancevillage/3rd/logx"
	"github.com/advancevillage/3rd/netx"
	"github.com/advancevillage/fw/proto"
)

var (
	HttpRequestBodyCode = uint32(1000)
	JsonFromatCode      = uint32(1100)
	NotSupportCode      = uint32(1101)
	FwUpdateCode        = uint32(1200)
	FwQueryCode         = uint32(1201)

	HttpRequestBodyErr = "read request body error"
	JsonFormatErr      = "json format error"
	NotSupportMsg      = "not support action error"
	FwUpdateMsg        = "update firewall error"
	FwQueryMsg         = "queryfirewall error"

	SrvOk  = uint32(http.StatusOK)
	SrvErr = uint32(http.StatusInternalServerError)
)

type updateFwRequest struct {
	proto.ActionRequest

	Version int             `json:"version"`
	Rules   []*proto.FwRule `json:"rules"`
}

type updateFwResponse struct {
	proto.ActionResponse
}

type queryFwRequest struct {
	proto.ActionRequest
}

type queryFwResponse struct {
	proto.ActionResponse
	Rules []*proto.FwRule
}

func (s *Srv) httpHandler(ctx context.Context, wr netx.IHTTPWriteReader) {
	//1. 解析参数
	var reply = &proto.ActionResponse{
		Code: SrvErr,
	}
	var b, err = wr.Read()
	if err != nil {
		reply.Errors = append(reply.Errors, &proto.Error{Code: HttpRequestBodyCode, Msg: HttpRequestBodyErr})
		wr.Write(http.StatusOK, reply)
		return
	}
	var req = &proto.ActionRequest{}
	err = json.Unmarshal(b, req)
	if err != nil {
		reply.Errors = append(reply.Errors, &proto.Error{Code: JsonFromatCode, Msg: JsonFormatErr})
		wr.Write(http.StatusOK, reply)
		return
	}
	//2. 提取TraceId
	var sctx = context.WithValue(ctx, logx.TraceId, req.GetTraceId())
	reply.TraceId = req.GetTraceId()

	//3. 请求处理
	switch req.GetAction() {
	case "UpdateFirewall":
		var (
			request  = &updateFwRequest{}
			response = &updateFwResponse{}
		)
		response.TraceId = reply.GetTraceId()

		err = json.Unmarshal(b, request)
		if err != nil {
			response.Code = SrvErr
			response.Errors = append(response.Errors, &proto.Error{Code: JsonFromatCode, Msg: JsonFormatErr})
			wr.Write(http.StatusOK, response)
		} else {
			response.Code = SrvOk
			s.updateFirewall(sctx, response, request)
		}

		wr.Write(http.StatusOK, response)
	case "QueryFirewall":
		var (
			request  = &queryFwRequest{}
			response = &queryFwResponse{}
		)
		response.TraceId = reply.GetTraceId()

		err = json.Unmarshal(b, request)
		if err != nil {
			response.Code = SrvErr
			response.Errors = append(response.Errors, &proto.Error{Code: JsonFromatCode, Msg: JsonFormatErr})
			wr.Write(http.StatusOK, response)
		} else {
			response.Code = SrvOk
			s.queryFirewall(sctx, response, request)
		}

		wr.Write(http.StatusOK, response)
	default:
		reply.Errors = append(reply.Errors, &proto.Error{Code: NotSupportCode, Msg: NotSupportMsg})
		wr.Write(http.StatusOK, reply)
	}
}

func (s *Srv) updateFirewall(ctx context.Context, response *updateFwResponse, request *updateFwRequest) {
	var err = s.fwCli.Write(ctx, request.Version, request.Rules)
	if err != nil {
		s.logger.Errorw(ctx, "update firewall fail", "err", err)
		response.Errors = append(response.Errors, &proto.Error{Code: FwUpdateCode, Msg: FwUpdateMsg})
		response.Code = SrvErr
	}
}

func (s *Srv) queryFirewall(ctx context.Context, response *queryFwResponse, request *queryFwRequest) {
	var rules, err = s.fwCli.Read(ctx)
	if err != nil {
		s.logger.Errorw(ctx, "query firewall fail", "err", err)
		response.Errors = append(response.Errors, &proto.Error{Code: FwQueryCode, Msg: FwQueryMsg})
		response.Code = SrvErr
	}
	response.Rules = rules
}
