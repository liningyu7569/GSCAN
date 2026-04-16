package cmd

import (
	"Going_Scan/internal/gping"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

var (
	gpingURL             string
	gpingIP              string
	gpingPort            int
	gpingProtocol        string
	gpingRoute           string
	gpingMethod          string
	gpingTemplate        string
	gpingUAMDB           string
	gpingUAMEndpoint     string
	gpingUAMService      string
	gpingUAMVerify       string
	gpingPickFirst       bool
	gpingPickIndex       int
	gpingHost            string
	gpingSNI             string
	gpingPath            string
	gpingBody            string
	gpingPayload         string
	gpingPayloadHex      string
	gpingReadBytes       int
	gpingHeaders         []string
	gpingVars            []string
	gpingRetries         int
	gpingTTL             int
	gpingTOS             int
	gpingIPID            int
	gpingDF              bool
	gpingBadSum          bool
	gpingSourcePort      int
	gpingTCPFlags        string
	gpingTCPSeq          int64
	gpingTCPAck          int64
	gpingTCPWindow       int
	gpingICMPID          int
	gpingICMPSeq         int
	gpingICMPType        int
	gpingICMPCode        int
	gpingAssert          string
	gpingOverrideService string
	gpingInsecure        bool
	gpingWriteUAM        bool
	gpingJSON            bool
	gpingTimeout         time.Duration
	gpingTemplateShow    string
	gpingCandidateLimit  int
	gpingHistoryLimit    int
	gpingHistoryRunID    string
	gpingHistoryVerbose  bool
)

var gpingCmd = &cobra.Command{
	Use:   "gping [url-or-ip]",
	Short: "Run targeted validation probes and write the result back into UAM",
	Example: `  goscan gping https://127.0.0.1:8443 --method http-head --route app --insecure
  goscan gping --ip 192.168.1.10 --port 443 --template uam/https-enrich --uam-db uam.db
  goscan gping --uam-endpoint host:192.168.1.10:tcp:443 --uam-db uam.db --method tls-handshake`,
	RunE: runGPing,
}

var gpingTemplatesCmd = &cobra.Command{
	Use:   "templates",
	Short: "List built-in gping templates or show one template in detail",
	RunE:  runGPingTemplates,
}

var gpingCandidatesCmd = &cobra.Command{
	Use:   "candidates",
	Short: "List UAM endpoints that match gping selection filters",
	RunE:  runGPingCandidates,
}

var gpingPreviewCmd = &cobra.Command{
	Use:   "preview [url-or-ip]",
	Short: "Resolve a target and show the planned gping actions without executing",
	RunE:  runGPingPreview,
}

var gpingHistoryCmd = &cobra.Command{
	Use:   "history",
	Short: "Read recent gping observations for a target from UAM",
	RunE:  runGPingHistory,
}

func init() {
	rootCmd.AddCommand(gpingCmd)
	gpingCmd.AddCommand(gpingTemplatesCmd, gpingCandidatesCmd, gpingPreviewCmd, gpingHistoryCmd)
	bindGPingExecutionFlags(gpingCmd.Flags())
	bindGPingExecutionFlags(gpingPreviewCmd.Flags())

	tf := gpingTemplatesCmd.Flags()
	tf.StringVar(&gpingTemplateShow, "show", "", "Show one built-in template in detail")
	tf.BoolVar(&gpingJSON, "json", false, "Print JSON instead of a text report")

	bindGPingCandidateFlags(gpingCandidatesCmd.Flags())
	_ = gpingCandidatesCmd.MarkFlagRequired("uam-db")

	bindGPingHistoryFlags(gpingHistoryCmd.Flags())
	_ = gpingHistoryCmd.MarkFlagRequired("uam-db")
}

func bindGPingExecutionFlags(f *pflag.FlagSet) {
	f.StringVar(&gpingURL, "url", "", "Target URL, such as https://192.168.1.10/health")
	f.StringVar(&gpingIP, "ip", "", "Target IPv4 address")
	f.IntVarP(&gpingPort, "port", "p", 0, "Target port")
	f.StringVar(&gpingProtocol, "protocol", "", "Target protocol: tcp, udp, icmp (defaults to tcp for literal targets)")
	f.StringVar(&gpingRoute, "route", "", "Execution route: raw, stack, app")
	f.StringVar(&gpingMethod, "method", "", "Method to run: tcp-syn, tcp-raw, icmp-echo-raw, icmp-raw, tcp-connect, banner-read, tls-handshake, http-head, http-get, http-post, dns-query, ftp-banner, ftp-feat, ftp-auth-tls, smtp-banner, smtp-ehlo, smtp-starttls, redis-ping, redis-info-server, redis-info-replication, ssh-banner, ssh-kexinit, ssh-hostkey, mysql-greeting, mysql-capabilities, mysql-starttls")
	f.StringVar(&gpingTemplate, "template", "", "Template name or yaml file path")
	f.StringVar(&gpingUAMDB, "uam-db", "", "Path to the UAM SQLite database")
	f.StringVar(&gpingUAMEndpoint, "uam-endpoint", "", "Resolve the target from a UAM endpoint id")
	f.StringVar(&gpingUAMService, "uam-service", "", "Select a target from UAM by current service name")
	f.StringVar(&gpingUAMVerify, "uam-verification-state", "", "Select a target from UAM by verification_state")
	f.BoolVar(&gpingPickFirst, "pick-first", false, "When a UAM filter matches multiple endpoints, pick the most recently seen one")
	f.IntVar(&gpingPickIndex, "pick-index", 0, "When a UAM filter matches multiple endpoints, pick the Nth candidate (1-based)")
	f.StringVar(&gpingHost, "host", "", "Optional Host header / logical hostname")
	f.StringVar(&gpingSNI, "sni", "", "Optional TLS SNI value")
	f.StringVar(&gpingPath, "path", "/", "Optional HTTP path override")
	f.StringVar(&gpingBody, "body", "", "Optional HTTP request body")
	f.StringVar(&gpingPayload, "payload", "", "Optional payload for methods that write to the connection")
	f.StringVar(&gpingPayloadHex, "payload-hex", "", "Optional raw payload bytes in hexadecimal form")
	f.IntVar(&gpingReadBytes, "read-bytes", 0, "Optional read size override for methods such as banner-read")
	f.StringArrayVar(&gpingHeaders, "header", nil, "HTTP header in key:value form")
	f.StringArrayVar(&gpingVars, "var", nil, "Template variable in key=value form")
	f.IntVar(&gpingRetries, "retries", 0, "Optional retry count for raw methods")
	f.IntVar(&gpingTTL, "ttl", -1, "Optional IPv4 TTL override for raw methods")
	f.IntVar(&gpingTOS, "tos", -1, "Optional IPv4 TOS/DSCP byte override for raw methods")
	f.IntVar(&gpingIPID, "ip-id", -1, "Optional IPv4 identification override for raw methods")
	f.BoolVar(&gpingDF, "df", false, "Set the IPv4 Don't Fragment flag on raw packets")
	f.BoolVar(&gpingBadSum, "badsum", false, "Intentionally corrupt the transport checksum on raw packets")
	f.IntVar(&gpingSourcePort, "source-port", -1, "Optional source port override for raw TCP methods")
	f.StringVar(&gpingTCPFlags, "tcp-flags", "", "Optional TCP flags for raw TCP methods, such as syn,ack or fin,psh,urg")
	f.Int64Var(&gpingTCPSeq, "tcp-seq", -1, "Optional TCP sequence number override for raw TCP methods")
	f.Int64Var(&gpingTCPAck, "tcp-ack", -1, "Optional TCP acknowledgment number override for raw TCP methods")
	f.IntVar(&gpingTCPWindow, "tcp-window", -1, "Optional TCP window override for raw TCP methods")
	f.IntVar(&gpingICMPID, "icmp-id", -1, "Optional ICMP identifier override for raw ICMP methods")
	f.IntVar(&gpingICMPSeq, "icmp-seq", -1, "Optional ICMP sequence override for raw ICMP methods")
	f.IntVar(&gpingICMPType, "icmp-type", -1, "Optional ICMP type override for raw ICMP methods")
	f.IntVar(&gpingICMPCode, "icmp-code", -1, "Optional ICMP code override for raw ICMP methods")
	f.StringVar(&gpingAssert, "assert", "", "Write a verification state into UAM: pending, confirmed, overridden")
	f.StringVar(&gpingOverrideService, "override-service", "", "Write a service override into UAM")
	f.BoolVar(&gpingInsecure, "insecure", false, "Skip TLS certificate verification")
	f.BoolVar(&gpingWriteUAM, "write-uam", true, "Write gping observations back into UAM when --uam-db is present")
	f.BoolVar(&gpingJSON, "json", false, "Print JSON instead of a text report")
	f.DurationVar(&gpingTimeout, "timeout", 5*time.Second, "Per-action timeout")
}

func bindGPingCandidateFlags(f *pflag.FlagSet) {
	f.StringVar(&gpingUAMDB, "uam-db", "", "Path to the UAM SQLite database")
	f.StringVar(&gpingIP, "ip", "", "Filter by IP")
	f.IntVarP(&gpingPort, "port", "p", 0, "Filter by port")
	f.StringVar(&gpingProtocol, "protocol", "", "Filter by protocol")
	f.StringVar(&gpingUAMService, "uam-service", "", "Filter by current service name")
	f.StringVar(&gpingUAMVerify, "uam-verification-state", "", "Filter by verification_state")
	f.IntVar(&gpingCandidateLimit, "limit", 20, "Maximum number of candidates to return")
	f.BoolVar(&gpingJSON, "json", false, "Print JSON instead of a text report")
}

func bindGPingHistoryFlags(f *pflag.FlagSet) {
	f.StringVar(&gpingUAMDB, "uam-db", "", "Path to the UAM SQLite database")
	f.StringVar(&gpingIP, "ip", "", "Filter by IP")
	f.IntVarP(&gpingPort, "port", "p", 0, "Filter by port")
	f.StringVar(&gpingProtocol, "protocol", "", "Filter by protocol")
	f.StringVar(&gpingHistoryRunID, "run-id", "", "Filter by gping run id")
	f.IntVar(&gpingHistoryLimit, "limit", 20, "Maximum number of observations to return")
	f.BoolVar(&gpingHistoryVerbose, "verbose", false, "Include stored extra_json evidence in text output")
	f.BoolVar(&gpingJSON, "json", false, "Print JSON instead of a text report")
}

func runGPing(cmd *cobra.Command, args []string) error {
	opts, err := buildGPingOptions(args)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	result, err := gping.Run(ctx, opts)
	if err != nil {
		return err
	}

	if opts.OutputJSON {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(result)
	}

	fmt.Fprint(os.Stdout, renderGPingResult(result))
	return nil
}

func buildGPingOptions(args []string) (gping.Options, error) {
	if len(args) > 1 {
		return gping.Options{}, fmt.Errorf("gping accepts at most one positional target")
	}

	headers := make(map[string]string)
	for _, raw := range gpingHeaders {
		parts := strings.SplitN(raw, ":", 2)
		if len(parts) != 2 {
			return gping.Options{}, fmt.Errorf("header must look like key:value")
		}
		headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
	}

	vars := make(map[string]string)
	for _, raw := range gpingVars {
		parts := strings.SplitN(raw, "=", 2)
		if len(parts) != 2 {
			return gping.Options{}, fmt.Errorf("var must look like key=value")
		}
		vars[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
	}

	options := gping.Options{
		Commandline:        strings.Join(os.Args, " "),
		URL:                strings.TrimSpace(gpingURL),
		IP:                 strings.TrimSpace(gpingIP),
		Port:               gpingPort,
		Protocol:           strings.TrimSpace(gpingProtocol),
		Route:              strings.TrimSpace(gpingRoute),
		Method:             strings.TrimSpace(gpingMethod),
		TemplateName:       strings.TrimSpace(gpingTemplate),
		UAMDBPath:          strings.TrimSpace(gpingUAMDB),
		UAMEndpoint:        strings.TrimSpace(gpingUAMEndpoint),
		UAMService:         strings.TrimSpace(gpingUAMService),
		UAMVerify:          strings.TrimSpace(gpingUAMVerify),
		PickFirst:          gpingPickFirst,
		PickIndex:          gpingPickIndex,
		HostHeader:         strings.TrimSpace(gpingHost),
		SNI:                strings.TrimSpace(gpingSNI),
		Path:               strings.TrimSpace(gpingPath),
		Body:               gpingBody,
		Payload:            gpingPayload,
		PayloadHex:         strings.TrimSpace(gpingPayloadHex),
		ReadBytes:          gpingReadBytes,
		Headers:            headers,
		Vars:               vars,
		Retries:            gpingRetries,
		TTL:                gpingTTL,
		TOS:                gpingTOS,
		IPID:               gpingIPID,
		DF:                 gpingDF,
		BadSum:             gpingBadSum,
		SourcePort:         gpingSourcePort,
		TCPFlags:           strings.TrimSpace(gpingTCPFlags),
		TCPSeq:             gpingTCPSeq,
		TCPAck:             gpingTCPAck,
		TCPWindow:          gpingTCPWindow,
		ICMPID:             gpingICMPID,
		ICMPSeq:            gpingICMPSeq,
		ICMPType:           gpingICMPType,
		ICMPCode:           gpingICMPCode,
		InsecureSkipVerify: gpingInsecure,
		WriteUAM:           gpingWriteUAM && strings.TrimSpace(gpingUAMDB) != "",
		OutputJSON:         gpingJSON,
		VerificationState:  strings.TrimSpace(gpingAssert),
		OverrideService:    strings.TrimSpace(gpingOverrideService),
		Timeout:            gpingTimeout,
	}

	if len(args) == 1 && options.URL == "" && options.IP == "" {
		positional := strings.TrimSpace(args[0])
		switch {
		case strings.Contains(positional, "://"):
			options.URL = positional
		case net.ParseIP(positional) != nil:
			options.IP = positional
		default:
			return gping.Options{}, fmt.Errorf("positional target must be a URL or IPv4 address")
		}
	}

	return options, nil
}

func runGPingTemplates(cmd *cobra.Command, _ []string) error {
	if strings.TrimSpace(gpingTemplateShow) != "" {
		spec, err := gping.LoadTemplate(strings.TrimSpace(gpingTemplateShow))
		if err != nil {
			return err
		}
		if gpingJSON {
			encoder := json.NewEncoder(os.Stdout)
			encoder.SetIndent("", "  ")
			return encoder.Encode(spec)
		}
		fmt.Fprint(os.Stdout, renderGPingTemplate(spec))
		return nil
	}

	items, err := gping.ListTemplateSummaries()
	if err != nil {
		return err
	}
	if gpingJSON {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(items)
	}
	fmt.Fprint(os.Stdout, renderGPingTemplateList(items))
	return nil
}

func runGPingCandidates(cmd *cobra.Command, _ []string) error {
	opts, err := buildGPingOptions(nil)
	if err != nil {
		return err
	}
	items, err := gping.ListCandidates(cmd.Context(), opts, gpingCandidateLimit)
	if err != nil {
		return err
	}
	if gpingJSON {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(items)
	}
	fmt.Fprint(os.Stdout, renderGPingCandidates(items))
	return nil
}

func runGPingPreview(cmd *cobra.Command, args []string) error {
	opts, err := buildGPingOptions(args)
	if err != nil {
		return err
	}

	preview, err := gping.Preview(cmd.Context(), opts)
	if err != nil {
		return err
	}

	if opts.OutputJSON {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(preview)
	}

	fmt.Fprint(os.Stdout, renderGPingPreview(preview))
	return nil
}

func runGPingHistory(cmd *cobra.Command, _ []string) error {
	history, err := gping.BuildHistory(cmd.Context(), strings.TrimSpace(gpingUAMDB), gping.HistoryFilter{
		IP:       strings.TrimSpace(gpingIP),
		Port:     gpingPort,
		Protocol: strings.TrimSpace(gpingProtocol),
		RunID:    strings.TrimSpace(gpingHistoryRunID),
	}, gpingHistoryLimit)
	if err != nil {
		return err
	}

	if gpingJSON {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(history)
	}

	fmt.Fprint(os.Stdout, gping.RenderHistory(history, gpingHistoryVerbose))
	return nil
}

func renderGPingResult(result gping.RunResult) string {
	var b strings.Builder
	fmt.Fprintf(&b, "gping target %s", result.Target.IP)
	if result.Target.Port > 0 {
		fmt.Fprintf(&b, ":%d/%s", result.Target.Port, result.Target.Protocol)
	}
	fmt.Fprintf(&b, "  source=%s\n", result.Target.Source)
	if result.TemplateName != "" {
		fmt.Fprintf(&b, "template: %s\n", result.TemplateName)
	}
	if result.UAMRunID != "" {
		fmt.Fprintf(&b, "uam run: %s\n", result.UAMRunID)
	}
	if len(result.Recommendations) > 0 {
		b.WriteString("recommendations:\n")
		for _, item := range result.Recommendations {
			parts := make([]string, 0, 2)
			if item.VerificationState != "" {
				parts = append(parts, "verification_state="+item.VerificationState)
			}
			if item.OverrideService != "" {
				parts = append(parts, "override_service_name="+item.OverrideService)
			}
			fmt.Fprintf(&b, "  %s", strings.Join(parts, "  "))
			if item.Reason != "" {
				fmt.Fprintf(&b, "  (%s)", item.Reason)
			}
			b.WriteString("\n")
		}
	}
	b.WriteString("\n")

	for index, report := range result.Reports {
		fmt.Fprintf(&b, "%d. %s/%s -> %s", index+1, report.RouteUsed, report.RawMethod, report.RawStatus)
		if report.StepID != "" {
			fmt.Fprintf(&b, "  [step=%s]", report.StepID)
		}
		if report.RTTMs != nil {
			fmt.Fprintf(&b, " (%.1f ms)", *report.RTTMs)
		}
		b.WriteString("\n")
		if report.RequestSummary != "" {
			fmt.Fprintf(&b, "   request: %s\n", report.RequestSummary)
		}
		if report.ResponseSummary != "" {
			fmt.Fprintf(&b, "   response: %s\n", report.ResponseSummary)
		}
		if report.ErrorText != "" {
			fmt.Fprintf(&b, "   error: %s\n", report.ErrorText)
		}
		if len(report.Claims) > 0 {
			parts := make([]string, 0, len(report.Claims))
			for _, claim := range report.Claims {
				label := claim.Namespace + "." + claim.Name
				value := claim.ValueText
				if value == "" && claim.ValueJSON != "" {
					value = claim.ValueJSON
				}
				parts = append(parts, fmt.Sprintf("%s=%s", label, value))
			}
			fmt.Fprintf(&b, "   claims: %s\n", strings.Join(parts, ", "))
		}
		b.WriteString("\n")
	}

	return strings.TrimRight(b.String(), "\n") + "\n"
}

func renderGPingTemplateList(items []gping.TemplateSummary) string {
	var b strings.Builder
	if len(items) == 0 {
		return "no built-in gping templates found\n"
	}
	b.WriteString("gping templates\n\n")
	for _, item := range items {
		fmt.Fprintf(&b, "- %s  routes=%s  actions=%d\n", item.Name, strings.Join(item.Routes, ","), item.ActionCount)
		if item.Description != "" {
			fmt.Fprintf(&b, "  %s\n", item.Description)
		}
	}
	return strings.TrimRight(b.String(), "\n") + "\n"
}

func renderGPingTemplate(spec gping.TemplateSpec) string {
	var b strings.Builder
	fmt.Fprintf(&b, "template: %s\n", spec.Name)
	if spec.Description != "" {
		fmt.Fprintf(&b, "description: %s\n", spec.Description)
	}
	if spec.Kind != "" {
		fmt.Fprintf(&b, "kind: %s\n", spec.Kind)
	}
	if !spec.AppliesTo.IsZero() {
		b.WriteString("applies_to:\n")
		if spec.AppliesTo.Protocol != "" {
			fmt.Fprintf(&b, "  protocol=%s\n", spec.AppliesTo.Protocol)
		}
		if len(spec.AppliesTo.Ports) > 0 {
			fmt.Fprintf(&b, "  ports=%v\n", spec.AppliesTo.Ports)
		}
		if len(spec.AppliesTo.CurrentService) > 0 {
			fmt.Fprintf(&b, "  current_service=%s\n", strings.Join(spec.AppliesTo.CurrentService, ","))
		}
		if len(spec.AppliesTo.Scheme) > 0 {
			fmt.Fprintf(&b, "  scheme=%s\n", strings.Join(spec.AppliesTo.Scheme, ","))
		}
	}
	if len(spec.Vars) > 0 {
		b.WriteString("vars:\n")
		keys := make([]string, 0, len(spec.Vars))
		for key := range spec.Vars {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			value := spec.Vars[key]
			parts := make([]string, 0, 4)
			if value.Default != "" {
				parts = append(parts, "default="+value.Default)
			}
			if value.DefaultFrom != "" {
				parts = append(parts, "default_from="+value.DefaultFrom)
			}
			if value.Type != "" {
				parts = append(parts, "type="+value.Type)
			}
			if value.Required {
				parts = append(parts, "required=true")
			}
			fmt.Fprintf(&b, "  %s", key)
			if len(parts) > 0 {
				fmt.Fprintf(&b, "  %s", strings.Join(parts, "  "))
			}
			if value.Description != "" {
				fmt.Fprintf(&b, "  # %s", value.Description)
			}
			b.WriteString("\n")
		}
	}
	steps := spec.Steps()
	if len(steps) > 0 {
		b.WriteString("workflow:\n")
		for index, action := range steps {
			fmt.Fprintf(&b, "  %d. %s/%s\n", index+1, action.Route, action.Method)
			if action.ID != "" {
				fmt.Fprintf(&b, "     id=%s\n", action.ID)
			}
			if action.Adapter != "" {
				fmt.Fprintf(&b, "     adapter=%s\n", action.Adapter)
			}
			if action.URL != "" {
				fmt.Fprintf(&b, "     url=%s\n", action.URL)
			}
			if action.Path != "" {
				fmt.Fprintf(&b, "     path=%s\n", action.Path)
			}
			if action.Body != "" {
				fmt.Fprintf(&b, "     body=%q\n", summarizeLiteral(action.Body, 120))
			}
			if action.Payload != "" {
				fmt.Fprintf(&b, "     payload=%q\n", action.Payload)
			}
			if action.ReadBytes > 0 {
				fmt.Fprintf(&b, "     read_bytes=%d\n", action.ReadBytes)
			}
			if action.HostHeader != "" {
				fmt.Fprintf(&b, "     host=%s\n", action.HostHeader)
			}
			if action.SNI != "" {
				fmt.Fprintf(&b, "     sni=%s\n", action.SNI)
			}
			if len(action.Params) > 0 {
				fmt.Fprintf(&b, "     params=%v\n", action.Params)
			}
			if action.When != "" {
				fmt.Fprintf(&b, "     when=%s\n", action.When)
			}
			if action.ContinueOnError {
				b.WriteString("     continue_on_error=true\n")
			}
		}
	}
	if len(spec.Extract) > 0 {
		b.WriteString("extract:\n")
		for _, item := range spec.Extract {
			fmt.Fprintf(&b, "  from=%s  field=%s  to_claim=%s\n", item.From, item.Field, item.ToClaim)
		}
	}
	if len(spec.Suggest) > 0 {
		b.WriteString("suggest:\n")
		keys := make([]string, 0, len(spec.Suggest))
		for key := range spec.Suggest {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			fmt.Fprintf(&b, "  %s=%s\n", key, spec.Suggest[key])
		}
	}
	if len(spec.Recommend.ResolvedValues()) > 0 {
		b.WriteString("recommend:\n")
		values := spec.Recommend.ResolvedValues()
		keys := make([]string, 0, len(values))
		for key := range values {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			value := values[key]
			fmt.Fprintf(&b, "  %s=%s\n", key, value)
		}
		if len(spec.Recommend.WhenAll) > 0 {
			fmt.Fprintf(&b, "  when_all=%s\n", strings.Join(spec.Recommend.WhenAll, " && "))
		}
	}
	return strings.TrimRight(b.String(), "\n") + "\n"
}

func renderGPingCandidates(items []gping.Candidate) string {
	var b strings.Builder
	if len(items) == 0 {
		return "no gping candidates matched\n"
	}
	b.WriteString("gping candidates\n\n")
	b.WriteString("Use --pick-index N or --uam-endpoint <id> to select one candidate.\n\n")
	for index, item := range items {
		fmt.Fprintf(&b, "%d. %s  %s:%d/%s  service=%s  verify=%s\n",
			index+1,
			item.EndpointID,
			item.IP,
			item.Port,
			item.Protocol,
			stringOrDash(item.CurrentService),
			stringOrDash(item.VerificationState),
		)
		meta := make([]string, 0, 4)
		if item.CurrentProduct != "" {
			meta = append(meta, "product="+item.CurrentProduct)
		}
		if item.CurrentVersion != "" {
			meta = append(meta, "version="+item.CurrentVersion)
		}
		if item.SourceTool != "" {
			meta = append(meta, "source="+item.SourceTool)
		}
		if item.LastSeenAt != "" {
			meta = append(meta, "last_seen="+item.LastSeenAt)
		}
		if item.CurrentBanner != "" {
			meta = append(meta, "banner="+item.CurrentBanner)
		}
		if len(item.SuggestedTemplates) > 0 {
			meta = append(meta, "templates="+strings.Join(item.SuggestedTemplates, ","))
		}
		if len(meta) > 0 {
			fmt.Fprintf(&b, "   %s\n", strings.Join(meta, "  "))
		}
	}
	return strings.TrimRight(b.String(), "\n") + "\n"
}

func renderGPingPreview(preview gping.PreviewResult) string {
	var b strings.Builder
	b.WriteString("gping preview\n\n")

	fmt.Fprintf(&b, "target: %s", preview.Target.IP)
	if preview.Target.Port > 0 {
		fmt.Fprintf(&b, ":%d/%s", preview.Target.Port, preview.Target.Protocol)
	}
	fmt.Fprintf(&b, "  source=%s\n", preview.Target.Source)
	if preview.Target.UAMEndpointID != "" {
		fmt.Fprintf(&b, "uam endpoint: %s\n", preview.Target.UAMEndpointID)
	}
	if preview.Target.CurrentService != "" {
		fmt.Fprintf(&b, "current service: %s\n", preview.Target.CurrentService)
	}
	if preview.Target.CurrentProduct != "" {
		fmt.Fprintf(&b, "current product: %s\n", preview.Target.CurrentProduct)
	}
	if preview.Target.CurrentVersion != "" {
		fmt.Fprintf(&b, "current version: %s\n", preview.Target.CurrentVersion)
	}
	if preview.Target.CurrentBanner != "" {
		fmt.Fprintf(&b, "current banner: %s\n", preview.Target.CurrentBanner)
	}
	if preview.Target.VerificationState != "" {
		fmt.Fprintf(&b, "verification state: %s\n", preview.Target.VerificationState)
	}
	if preview.Target.URL != "" {
		fmt.Fprintf(&b, "url: %s\n", preview.Target.URL)
	}
	if len(preview.SuggestedTemplates) > 0 {
		fmt.Fprintf(&b, "suggested templates: %s\n", strings.Join(preview.SuggestedTemplates, ", "))
	}
	if len(preview.OperatorAssertions) > 0 {
		fmt.Fprintf(&b, "operator assertions: %s\n", strings.Join(preview.OperatorAssertions, ", "))
	}
	if preview.WriteUAM {
		b.WriteString("uam writeback: enabled\n")
	} else {
		b.WriteString("uam writeback: disabled\n")
	}

	if preview.TemplateName != "" {
		fmt.Fprintf(&b, "template: %s\n", preview.TemplateName)
	}
	if len(preview.TemplateSuggest) > 0 {
		keys := make([]string, 0, len(preview.TemplateSuggest))
		for key := range preview.TemplateSuggest {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		b.WriteString("template suggest:\n")
		for _, key := range keys {
			fmt.Fprintf(&b, "  %s=%s\n", key, preview.TemplateSuggest[key])
		}
	}
	if len(preview.TemplateRecommend) > 0 {
		keys := make([]string, 0, len(preview.TemplateRecommend))
		for key := range preview.TemplateRecommend {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		b.WriteString("template recommend:\n")
		for _, key := range keys {
			fmt.Fprintf(&b, "  %s=%s\n", key, preview.TemplateRecommend[key])
		}
	}

	b.WriteString("\n")
	if len(preview.Actions) == 0 {
		b.WriteString("no actions planned yet; specify --method or --template to build a run plan.\n")
		return b.String()
	}

	b.WriteString("actions:\n")
	for index, action := range preview.Actions {
		fmt.Fprintf(&b, "  %d. %s/%s\n", index+1, action.Route, action.Method)
		if action.ID != "" {
			fmt.Fprintf(&b, "     id=%s\n", action.ID)
		}
		if action.Adapter != "" {
			fmt.Fprintf(&b, "     adapter=%s\n", action.Adapter)
		}
		if action.URL != "" {
			fmt.Fprintf(&b, "     url=%s\n", action.URL)
		}
		if action.Path != "" {
			fmt.Fprintf(&b, "     path=%s\n", action.Path)
		}
		if action.Body != "" {
			fmt.Fprintf(&b, "     body=%q\n", summarizeLiteral(action.Body, 120))
		}
		if action.Payload != "" {
			fmt.Fprintf(&b, "     payload=%q\n", action.Payload)
		}
		if action.ReadBytes > 0 {
			fmt.Fprintf(&b, "     read_bytes=%d\n", action.ReadBytes)
		}
		if action.HostHeader != "" {
			fmt.Fprintf(&b, "     host=%s\n", action.HostHeader)
		}
		if action.SNI != "" {
			fmt.Fprintf(&b, "     sni=%s\n", action.SNI)
		}
		if len(action.Params) > 0 {
			fmt.Fprintf(&b, "     params=%v\n", action.Params)
		}
		if action.When != "" {
			fmt.Fprintf(&b, "     when=%s\n", action.When)
		}
		if action.ContinueOnError {
			b.WriteString("     continue_on_error=true\n")
		}
		if action.Timeout > 0 {
			fmt.Fprintf(&b, "     timeout=%s\n", action.Timeout)
		}
		if action.InsecureSkipVerify {
			b.WriteString("     insecure_skip_verify=true\n")
		}
	}

	return strings.TrimRight(b.String(), "\n") + "\n"
}

func stringOrDash(value string) string {
	if strings.TrimSpace(value) == "" {
		return "-"
	}
	return value
}

func summarizeLiteral(value string, limit int) string {
	value = strings.TrimSpace(value)
	if limit <= 0 || len(value) <= limit {
		return value
	}
	return value[:limit] + "..."
}
