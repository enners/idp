package oidc

import (
	"errors"
	"fmt"
)

func makeFlowHandler(fs FlowSpec) FlowAction {
	fh := dummyAction
	fh = makeClientApprover(fs)(fh)
	return fh
}

func dummyAction(as *AuthzSession) error {
	fmt.Println("in dummy action")
	return errors.New("test term on 1st error")
}

func makeClientApprover(fs FlowSpec) FlowProcessor {
	return func(next FlowAction) FlowAction {
		return func(as *AuthzSession) error {
			defer fmt.Println("in flow action client approver")
			as.Phase = CLIENT_APPROVED
			return next(as)
		}
	}
}

func validateClient(as *AuthzSession) error {
	defer fmt.Printf("client %v approved \n", as.Client.Name)
	return nil
}
