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
	if _, err := fmt.Fprintln(tw, "CASE\tECOSYSTEM\tSOURCE\tSTATUS\tPACKAGES\tEDGES\tOVERALL\tEXACT\tVERSIONS\tSOURCE-ONLY\tBOMLY-ONLY\tIGNORED(B/S)"); err != nil {
		return err
	}
	for _, benchmarkCase := range summary.Cases {
		if len(benchmarkCase.Sources) == 0 {
			if _, err := fmt.Fprintf(tw, "%s\t%s\t-\t%s\t-\t-\t-\t-\t-\t-\t-\t-\n", benchmarkCase.Case, benchmarkCase.Ecosystem, benchmarkCase.Status); err != nil {
				return err
			}
			continue
		}
		for _, source := range benchmarkCase.Sources {
			packageScore, edgeScore, overallScore := "-", "-", "-"
			exact, versions, sourceOnly, bomlyOnly := "-", "-", "-", "-"
			ignored := "-"
			if source.Scores != nil && source.Packages != nil {
				packageScore = scoreCell(source.Scores.Package)
				edgeScore = optionalScoreCell(source.Scores.Relationship)
				overallScore = scoreCell(source.Scores.Overall)
				exact = fmt.Sprint(source.Packages.ExactMatches)
				versions = fmt.Sprint(source.Packages.VersionMismatch)
				sourceOnly = fmt.Sprint(source.Packages.SourceOnly)
				bomlyOnly = fmt.Sprint(source.Packages.BomlyOnly)
				ignored = fmt.Sprintf("%d/%d", source.Packages.BomlyIgnored, source.Packages.SourceIgnored)
			}
			if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
				benchmarkCase.Case, benchmarkCase.Ecosystem, source.Source, source.Status, packageScore, edgeScore, overallScore, exact, versions, sourceOnly, bomlyOnly, ignored); err != nil {
				return err
			}
		}
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	if summary.Scores != nil {
		_, err := fmt.Fprintf(w, "\nOverall score: %s (packages %s, edges %s)\n", scoreCell(summary.Scores.Overall), scoreCell(summary.Scores.Package), optionalScoreCell(summary.Scores.Relationship))
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
