// Package sarifdoc holds minimal SARIF 2.1.0 JSON types for marshaling.
// It does NOT convert SCINTX Findings — each provider maps its own native
// output into these structs (or passthroughs tool-emitted SARIF bytes).
package sarifdoc

import "encoding/json"

const (
	Version = "2.1.0"
	Schema  = "https://json.schemastore.org/sarif-2.1.0.json"
)

// Document is a SARIF log file root.
type Document struct {
	Version string `json:"version"`
	Schema  string `json:"$schema,omitempty"`
	Runs    []Run  `json:"runs"`
}

type Run struct {
	Tool    Tool     `json:"tool"`
	Results []Result `json:"results,omitempty"`
}

type Tool struct {
	Driver ToolComponent `json:"driver"`
}

type ToolComponent struct {
	Name           string `json:"name"`
	Version        string `json:"version,omitempty"`
	InformationURI string `json:"informationUri,omitempty"`
	Rules          []Rule `json:"rules,omitempty"`
}

type Rule struct {
	ID               string         `json:"id"`
	Name             string         `json:"name,omitempty"`
	ShortDescription *Message       `json:"shortDescription,omitempty"`
	FullDescription  *Message       `json:"fullDescription,omitempty"`
	DefaultConfig    *ReportingConfig `json:"defaultConfiguration,omitempty"`
	HelpURI          string         `json:"helpUri,omitempty"`
	Properties       map[string]any `json:"properties,omitempty"`
}

type ReportingConfig struct {
	Level string `json:"level,omitempty"`
}

type Result struct {
	RuleID     string         `json:"ruleId,omitempty"`
	Level      string         `json:"level,omitempty"` // error, warning, note, none
	Message    Message        `json:"message"`
	Locations  []Location     `json:"locations,omitempty"`
	Properties map[string]any `json:"properties,omitempty"`
}

type Message struct {
	Text string `json:"text,omitempty"`
}

type Location struct {
	PhysicalLocation *PhysicalLocation `json:"physicalLocation,omitempty"`
}

type PhysicalLocation struct {
	ArtifactLocation *ArtifactLocation `json:"artifactLocation,omitempty"`
	Region           *Region           `json:"region,omitempty"`
}

type ArtifactLocation struct {
	URI string `json:"uri,omitempty"`
}

type Region struct {
	StartLine   int `json:"startLine,omitempty"`
	StartColumn int `json:"startColumn,omitempty"`
	EndLine     int `json:"endLine,omitempty"`
}

// Marshal returns compact SARIF JSON for AttachRawReport.
func Marshal(doc Document) ([]byte, error) {
	if doc.Version == "" {
		doc.Version = Version
	}
	if doc.Schema == "" {
		doc.Schema = Schema
	}
	return json.Marshal(doc)
}

// LevelFromSeverity maps common provider severity strings to SARIF levels.
func LevelFromSeverity(sev string) string {
	switch sev {
	case "critical", "CRITICAL", "Critical", "high", "HIGH", "High", "error", "Error":
		return "error"
	case "medium", "MEDIUM", "Medium", "warning", "Warning", "moderate", "Moderate":
		return "warning"
	case "low", "LOW", "Low", "note", "Note", "info", "Info", "negligible", "Negligible":
		return "note"
	default:
		return "warning"
	}
}
