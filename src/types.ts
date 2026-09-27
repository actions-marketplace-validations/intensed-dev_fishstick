export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface Finding {
  ruleId: string;
  severity: Severity;
  title: string;
  message: string;
  suggestion?: string;
  file: string;
  line: number;
  column?: number;
}

export interface ScanContext {
  file: string;
  content: string;
}

export interface Rule {
  id: string;
  title: string;
  severity: Severity;
  extensions: string[];
  scan(context: ScanContext): Finding[];
}
