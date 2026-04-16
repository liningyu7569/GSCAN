package gping

import (
	"context"
	"fmt"
)

func executeApp(ctx context.Context, target TargetContext, action ActionUnit) (routeEvidence, error) {
	adapter, err := adapterForAction(action)
	if err != nil {
		return routeEvidence{}, err
	}

	result, err := adapter.Execute(ctx, buildAppRequest(target, action))
	if err != nil {
		return routeEvidence{}, fmt.Errorf("%s adapter %s failed: %w", adapter.Name(), action.Method, err)
	}

	return routeEvidence{
		RawStatus:       result.RawStatus,
		RequestSummary:  result.RequestSummary,
		ResponseSummary: result.ResponseSummary,
		RTTMs:           result.RTTMs,
		ErrorText:       result.ErrorText,
		Fields:          result.Fields,
		Extra:           result.Extra,
		StatusCode:      intAny(result.Fields["status_code"]),
		Server:          stringAny(result.Fields["server"]),
		Location:        stringAny(result.Fields["location"]),
		Title:           stringAny(result.Fields["title"]),
		BodyPreview:     stringAny(result.Fields["body_preview"]),
		Banner:          stringAny(result.Fields["banner"]),
		Product:         stringAny(result.Fields["product"]),
		Version:         stringAny(result.Fields["version"]),
		TLSSubject:      stringAny(result.Fields["tls_subject"]),
		TLSIssuer:       stringAny(result.Fields["tls_issuer"]),
		TLSSANs:         stringSliceAny(result.Fields["tls_san"]),
		TLSALPN:         stringAny(result.Fields["tls_alpn"]),
		TLSVersion:      stringAny(result.Fields["tls_version"]),
	}, nil
}
