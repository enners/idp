package provider

import (
	"errors"
	"fmt"

	"github.com/ennersk/idp/oidc"
)

func newAuthzStarter(rts []string, gts []string, extGrantsSupported bool) FlowAction {
	a := nextFlowStep(oidc.FP_AUTHZ_CLIENT)
	a = responseTypesSupported(rts)(a)
	return a
}

func responseTypesSupported(rts []string) FlowProcessor {
	m := asResponseTypeMap(rts)
	return func(next FlowAction) FlowAction {
		return func(as *oidc.AuthzSession) error {
			for _, rt := range as.AuthReq.ResponseTypes {
				if !m[rt] {
					return errors.New("unsupported response_type")
				}
			}
			return next(as)
		}
	}
}

func asResponseTypeMap(rts []string) map[oidc.ResponseType]bool {
	m := make(map[oidc.ResponseType]bool)
	for _, v := range rts {
		switch v {
		case "code":
			m[oidc.RT_CODE] = true
		case "token":
			m[oidc.RT_TOKEN] = true
		case "id_token":
			m[oidc.RT_IDTOKEN] = true
		case "none":
			m[oidc.RT_NONE] = true
		}
	}
	return m
}

func newClientApprover() FlowAction {
	a := nextFlowStep(oidc.FP_AQUIRING_SUBJECT)
	a = approveClient()(a)
	return a
}

func approveClient() FlowProcessor {
	return func(next FlowAction) FlowAction {
		return func(as *oidc.AuthzSession) error {
			m := asResponseTypeMap(as.Client.ResponseTypes)
			for _, r := range as.AuthReq.ResponseTypes {
				if !m[r] {
					return errors.New("forbidden: client not allowed for RT")
				}
			}
			return next(as)
		}
	}
}

func newFlowHandler(fs oidc.FlowSpec) map[string]FlowAction {
	switch fs {
	case oidc.CODE:
		return newCodeFlowActions()
	}
	return nil
}

func newCodeFlowActions() map[string]FlowAction {
	m := make(map[string]FlowAction)
	return m
}

func makeFlowHandler(fs oidc.FlowSpec) FlowAction {
	switch fs {
	case oidc.CODE:
		return makeCodeFlowHandler()
	}
	return nil
}

func makeCodeFlowHandler() FlowAction {
	fh := nextFlowStep(oidc.GRANTING)
	fh = makeClientApprover(oidc.CODE)(fh)
	return fh
}

func nextFlowStep(phase oidc.FlowPhase) FlowAction {
	return func(as *oidc.AuthzSession) error {
		as.Phase = phase
		return nil
	}
}

func makeClientApprover(fs oidc.FlowSpec) FlowProcessor {
	return func(next FlowAction) FlowAction {
		return func(as *oidc.AuthzSession) error {
			fmt.Println("in flow action client approver; flow step: %v", fs)
			err := errors.New("kick out of action")
			if err != nil {
				return next(as)
			}
			as.Phase = oidc.CLIENT_APPROVED
			return next(as)
		}
	}
}

func validateClient(as *oidc.AuthzSession) error {
	defer fmt.Printf("client %v approved \n", as.Client.Name)
	return nil
}
