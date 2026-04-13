package cmd

import (
	"Going_Scan/internal/uam/service"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var (
	uamDBPath        string
	uamLimit         int
	uamQueryIP       string
	uamQueryProtocol string
	uamQueryTool     string
	uamQueryRunID    string
	uamQueryPort     int
)

var uamCmd = &cobra.Command{
	Use:   "uam",
	Short: "Inspect the UAM SQLite asset store",
}

var uamRunsCmd = &cobra.Command{
	Use:   "runs",
	Short: "List recent runs from the UAM database",
	RunE: func(cmd *cobra.Command, args []string) error {
		return withQueryService(func(q *service.QueryService) error {
			payload, err := q.ListRunsFiltered(cmd.Context(), currentQueryFilter(), uamLimit)
			if err != nil {
				return err
			}
			return printJSON(payload)
		})
	},
}

var uamHostsCmd = &cobra.Command{
	Use:   "hosts",
	Short: "List current host projections from the UAM database",
	RunE: func(cmd *cobra.Command, args []string) error {
		return withQueryService(func(q *service.QueryService) error {
			payload, err := q.ListHostsFiltered(cmd.Context(), currentQueryFilter(), uamLimit)
			if err != nil {
				return err
			}
			return printJSON(payload)
		})
	},
}

var uamEndpointsCmd = &cobra.Command{
	Use:   "endpoints",
	Short: "List current endpoint projections from the UAM database",
	RunE: func(cmd *cobra.Command, args []string) error {
		return withQueryService(func(q *service.QueryService) error {
			payload, err := q.ListEndpointsFiltered(cmd.Context(), currentQueryFilter(), uamLimit)
			if err != nil {
				return err
			}
			return printJSON(payload)
		})
	},
}

var uamObservationsCmd = &cobra.Command{
	Use:   "observations",
	Short: "List recent observations from the UAM database",
	RunE: func(cmd *cobra.Command, args []string) error {
		return withQueryService(func(q *service.QueryService) error {
			payload, err := q.ListObservationsFiltered(cmd.Context(), currentQueryFilter(), uamLimit)
			if err != nil {
				return err
			}
			return printJSON(payload)
		})
	},
}

var uamReportCmd = &cobra.Command{
	Use:   "report",
	Short: "Render a human-readable host report from the UAM database",
	RunE: func(cmd *cobra.Command, args []string) error {
		if strings.TrimSpace(uamQueryIP) == "" {
			return fmt.Errorf("--ip is required for uam report")
		}
		return withQueryService(func(q *service.QueryService) error {
			report, err := q.BuildHostReport(cmd.Context(), currentQueryFilter(), maxInt(uamLimit, 100))
			if err != nil {
				return err
			}
			fmt.Fprint(os.Stdout, service.RenderHostReport(report))
			return nil
		})
	},
}

func init() {
	rootCmd.AddCommand(uamCmd)
	uamCmd.AddCommand(uamRunsCmd, uamHostsCmd, uamEndpointsCmd, uamObservationsCmd, uamReportCmd)

	registerUAMBaseFlags(uamRunsCmd)
	registerUAMBaseFlags(uamHostsCmd)
	registerUAMBaseFlags(uamEndpointsCmd)
	registerUAMBaseFlags(uamObservationsCmd)
	registerUAMBaseFlags(uamReportCmd)

	registerRunFilters(uamRunsCmd)
	registerHostFilters(uamHostsCmd)
	registerEndpointFilters(uamEndpointsCmd)
	registerObservationFilters(uamObservationsCmd)
	registerEndpointFilters(uamReportCmd)
	_ = uamReportCmd.MarkFlagRequired("ip")
}

func registerUAMBaseFlags(command *cobra.Command) {
	command.Flags().StringVar(&uamDBPath, "db", "", "Path to the UAM SQLite database")
	command.Flags().IntVar(&uamLimit, "limit", 20, "Maximum number of rows to return")
	_ = command.MarkFlagRequired("db")
}

func registerRunFilters(command *cobra.Command) {
	command.Flags().StringVar(&uamQueryIP, "ip", "", "Filter by IP")
	command.Flags().IntVar(&uamQueryPort, "port", 0, "Filter by port")
	command.Flags().StringVar(&uamQueryProtocol, "protocol", "", "Filter by protocol")
	command.Flags().StringVar(&uamQueryTool, "tool", "", "Filter by tool")
	command.Flags().StringVar(&uamQueryRunID, "run-id", "", "Filter by run id")
}

func registerHostFilters(command *cobra.Command) {
	command.Flags().StringVar(&uamQueryIP, "ip", "", "Filter by IP")
	command.Flags().IntVar(&uamQueryPort, "port", 0, "Filter by port")
	command.Flags().StringVar(&uamQueryProtocol, "protocol", "", "Filter by protocol")
	command.Flags().StringVar(&uamQueryTool, "tool", "", "Filter by tool")
	command.Flags().StringVar(&uamQueryRunID, "run-id", "", "Filter by run id")
}

func registerEndpointFilters(command *cobra.Command) {
	command.Flags().StringVar(&uamQueryIP, "ip", "", "Filter by IP")
	command.Flags().IntVar(&uamQueryPort, "port", 0, "Filter by port")
	command.Flags().StringVar(&uamQueryProtocol, "protocol", "", "Filter by protocol")
	command.Flags().StringVar(&uamQueryTool, "tool", "", "Filter by tool")
	command.Flags().StringVar(&uamQueryRunID, "run-id", "", "Filter by run id")
}

func registerObservationFilters(command *cobra.Command) {
	command.Flags().StringVar(&uamQueryIP, "ip", "", "Filter by IP")
	command.Flags().IntVar(&uamQueryPort, "port", 0, "Filter by port")
	command.Flags().StringVar(&uamQueryProtocol, "protocol", "", "Filter by protocol")
	command.Flags().StringVar(&uamQueryTool, "tool", "", "Filter by tool")
	command.Flags().StringVar(&uamQueryRunID, "run-id", "", "Filter by run id")
}

func currentQueryFilter() service.QueryFilter {
	return service.QueryFilter{
		IP:       strings.TrimSpace(uamQueryIP),
		Port:     uamQueryPort,
		Protocol: strings.ToLower(strings.TrimSpace(uamQueryProtocol)),
		Tool:     strings.TrimSpace(uamQueryTool),
		RunID:    strings.TrimSpace(uamQueryRunID),
	}
}

func withQueryService(fn func(*service.QueryService) error) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	queryService, err := service.OpenQueryService(uamDBPath)
	if err != nil {
		return err
	}
	defer queryService.Close()

	if err := queryService.MustOpen(ctx); err != nil {
		return err
	}

	return fn(queryService)
}

func printJSON(payload any) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(payload); err != nil {
		return fmt.Errorf("encode json: %w", err)
	}
	return nil
}

func maxInt(a int, b int) int {
	if a > b {
		return a
	}
	return b
}
