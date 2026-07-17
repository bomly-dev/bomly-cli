package benchmark

import (
	"fmt"
	"io"
	"text/tabwriter"
)

// RenderText writes a compact benchmark score matrix.
func RenderText(w io.Writer, summary RunSummary) error {
	if _, err := fmt.Fprintf(w, "Bomly dependency benchmark: %s\nArtifacts: %s\n\n", summary.Status, summary.RunDir); err != nil {
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "CASE\tECOSYSTEM\tSOURCE\tSTATUS\tPACKAGES\tEDGES\tOVERALL\tAGREEMENT\tEXT(P/E)\tUNADJ(P/E)\tEXACT\tVERSIONS\tSOURCE-ONLY(P/E)\tBOMLY-ONLY(P/E)\tIGNORED(B/S)"); err != nil {
		return err
	}
	for _, benchmarkCase := range summary.Cases {
		if len(benchmarkCase.Sources) == 0 {
			if _, err := fmt.Fprintf(tw, "%s\t%s\t-\t%s\t-\t-\t-\t-\t-\t-\t-\t-\t-\t-\t-\n", benchmarkCase.Case, benchmarkCase.Ecosystem, benchmarkCase.Status); err != nil {
				return err
			}
			continue
		}
		for _, source := range benchmarkCase.Sources {
			packageScore, edgeScore, overallScore := "-", "-", "-"
			exact, versions, sourceOnly, bomlyOnly := "-", "-", "-", "-"
			ignored := "-"
			agreement, extensions, unadjudicated := "-", "-", "-"
			if source.Scores != nil {
				packageScore = scoreCell(source.Scores.Package)
				edgeScore = optionalScoreCell(source.Scores.Relationship)
				overallScore = scoreCell(source.Scores.Overall)
			}
			if source.Packages != nil {
				exact = fmt.Sprint(source.Packages.ExactMatches)
				versions = fmt.Sprint(source.Packages.VersionMismatch)
				ignored = fmt.Sprintf("%d/%d", source.Packages.BomlyIgnored, source.Packages.SourceIgnored)
				edgeExtensions := 0
				edgeUnadjudicated := 0
				edgeSourceOnly := 0
				edgeBomlyOnly := 0
				if source.Relationships != nil {
					edgeExtensions = source.Relationships.Extensions
					edgeUnadjudicated = source.Relationships.Unadjudicated
					edgeSourceOnly = source.Relationships.SourceOnly
					edgeBomlyOnly = source.Relationships.BomlyOnly
				}
				extensions = fmt.Sprintf("%d/%d", source.Packages.Extensions, edgeExtensions)
				unadjudicated = fmt.Sprintf("%d/%d", source.Packages.Unadjudicated, edgeUnadjudicated)
				sourceOnly = fmt.Sprintf("%d/%d", source.Packages.SourceOnly, edgeSourceOnly)
				bomlyOnly = fmt.Sprintf("%d/%d", source.Packages.BomlyOnly, edgeBomlyOnly)
			}
			if source.Agreement != nil {
				agreement = scoreCell(source.Agreement.Overall)
			}
			if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
				benchmarkCase.Case, benchmarkCase.Ecosystem, source.Source, source.Status, packageScore, edgeScore, overallScore, agreement, extensions, unadjudicated, exact, versions, sourceOnly, bomlyOnly, ignored); err != nil {
				return err
			}
		}
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	if summary.Scores != nil {
		agreement := "N/A"
		if summary.Agreement != nil {
			agreement = scoreCell(summary.Agreement.Overall)
		}
		_, err := fmt.Fprintf(w, "\nOverall correctness: %s (packages %s, edges %s); raw agreement: %s\n", scoreCell(summary.Scores.Overall), scoreCell(summary.Scores.Package), optionalScoreCell(summary.Scores.Relationship), agreement)
		return err
	}
	_, err := fmt.Fprintf(w, "\nOverall score: N/A\n")
	return err
}

func scoreCell(value float64) string { return fmt.Sprintf("%.1f", value) }

func optionalScoreCell(value *float64) string {
	if value == nil {
		return "N/A"
	}
	return scoreCell(*value)
}
