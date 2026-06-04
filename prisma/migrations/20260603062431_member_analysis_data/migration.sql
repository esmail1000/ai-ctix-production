-- CreateTable
CREATE TABLE "AnalysisReport" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "userId" TEXT NOT NULL,
    "slug" TEXT,
    "name" TEXT NOT NULL,
    "type" TEXT NOT NULL,
    "uploadedAt" TEXT NOT NULL,
    "owner" TEXT NOT NULL DEFAULT 'AI CTIX',
    "status" TEXT NOT NULL,
    "findingCount" INTEGER NOT NULL DEFAULT 0,
    "critical" INTEGER NOT NULL DEFAULT 0,
    "high" INTEGER NOT NULL DEFAULT 0,
    "medium" INTEGER NOT NULL DEFAULT 0,
    "low" INTEGER NOT NULL DEFAULT 0,
    "summary" TEXT NOT NULL DEFAULT '',
    "content" TEXT NOT NULL DEFAULT '',
    "sourceFileName" TEXT,
    "parsingStatus" TEXT NOT NULL DEFAULT 'parsed',
    "analysisVersion" INTEGER NOT NULL DEFAULT 1,
    "parserVersion" INTEGER,
    "parsingNotesJson" TEXT NOT NULL DEFAULT '[]',
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" DATETIME NOT NULL,
    CONSTRAINT "AnalysisReport_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);

-- CreateTable
CREATE TABLE "AnalysisFinding" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "userId" TEXT NOT NULL,
    "reportId" TEXT NOT NULL,
    "reportName" TEXT NOT NULL,
    "slug" TEXT,
    "title" TEXT NOT NULL,
    "cve" TEXT NOT NULL DEFAULT '',
    "severity" TEXT NOT NULL,
    "asset" TEXT NOT NULL,
    "score" INTEGER NOT NULL DEFAULT 0,
    "status" TEXT NOT NULL,
    "detectedAt" TEXT NOT NULL,
    "summary" TEXT NOT NULL DEFAULT '',
    "impact" TEXT NOT NULL DEFAULT '',
    "evidence" TEXT NOT NULL DEFAULT '',
    "remediation" TEXT NOT NULL DEFAULT '',
    "evidenceSentenceIndex" INTEGER,
    "historyJson" TEXT NOT NULL DEFAULT '[]',
    "reportedJson" TEXT NOT NULL DEFAULT '{}',
    "normalizationJson" TEXT NOT NULL DEFAULT '{}',
    "provenanceJson" TEXT NOT NULL DEFAULT '{}',
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" DATETIME NOT NULL,
    CONSTRAINT "AnalysisFinding_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User" ("id") ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT "AnalysisFinding_reportId_fkey" FOREIGN KEY ("reportId") REFERENCES "AnalysisReport" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);

-- CreateTable
CREATE TABLE "AnalysisRun" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "userId" TEXT NOT NULL,
    "reportId" TEXT NOT NULL,
    "runJson" TEXT NOT NULL DEFAULT '{}',
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "AnalysisRun_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User" ("id") ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT "AnalysisRun_reportId_fkey" FOREIGN KEY ("reportId") REFERENCES "AnalysisReport" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);

-- CreateTable
CREATE TABLE "AnalysisSummary" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "userId" TEXT NOT NULL,
    "reportId" TEXT NOT NULL,
    "summaryJson" TEXT NOT NULL DEFAULT '{}',
    "summaryMetaJson" TEXT NOT NULL DEFAULT '{}',
    "generatedAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" DATETIME NOT NULL,
    CONSTRAINT "AnalysisSummary_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User" ("id") ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT "AnalysisSummary_reportId_fkey" FOREIGN KEY ("reportId") REFERENCES "AnalysisReport" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);

-- CreateTable
CREATE TABLE "AnalysisRiskScore" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "userId" TEXT NOT NULL,
    "reportId" TEXT NOT NULL,
    "overallRiskScore" INTEGER,
    "overallRiskBand" TEXT,
    "riskJson" TEXT NOT NULL DEFAULT '{}',
    "riskMetaJson" TEXT NOT NULL DEFAULT '{}',
    "generatedAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" DATETIME NOT NULL,
    CONSTRAINT "AnalysisRiskScore_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User" ("id") ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT "AnalysisRiskScore_reportId_fkey" FOREIGN KEY ("reportId") REFERENCES "AnalysisReport" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);

-- CreateIndex
CREATE INDEX "AnalysisReport_userId_idx" ON "AnalysisReport"("userId");

-- CreateIndex
CREATE INDEX "AnalysisReport_uploadedAt_idx" ON "AnalysisReport"("uploadedAt");

-- CreateIndex
CREATE INDEX "AnalysisReport_status_idx" ON "AnalysisReport"("status");

-- CreateIndex
CREATE INDEX "AnalysisReport_slug_idx" ON "AnalysisReport"("slug");

-- CreateIndex
CREATE INDEX "AnalysisFinding_userId_idx" ON "AnalysisFinding"("userId");

-- CreateIndex
CREATE INDEX "AnalysisFinding_reportId_idx" ON "AnalysisFinding"("reportId");

-- CreateIndex
CREATE INDEX "AnalysisFinding_severity_idx" ON "AnalysisFinding"("severity");

-- CreateIndex
CREATE INDEX "AnalysisFinding_status_idx" ON "AnalysisFinding"("status");

-- CreateIndex
CREATE INDEX "AnalysisFinding_asset_idx" ON "AnalysisFinding"("asset");

-- CreateIndex
CREATE INDEX "AnalysisFinding_cve_idx" ON "AnalysisFinding"("cve");

-- CreateIndex
CREATE INDEX "AnalysisFinding_slug_idx" ON "AnalysisFinding"("slug");

-- CreateIndex
CREATE INDEX "AnalysisRun_userId_idx" ON "AnalysisRun"("userId");

-- CreateIndex
CREATE INDEX "AnalysisRun_reportId_idx" ON "AnalysisRun"("reportId");

-- CreateIndex
CREATE INDEX "AnalysisRun_createdAt_idx" ON "AnalysisRun"("createdAt");

-- CreateIndex
CREATE INDEX "AnalysisSummary_userId_idx" ON "AnalysisSummary"("userId");

-- CreateIndex
CREATE INDEX "AnalysisSummary_reportId_idx" ON "AnalysisSummary"("reportId");

-- CreateIndex
CREATE INDEX "AnalysisSummary_generatedAt_idx" ON "AnalysisSummary"("generatedAt");

-- CreateIndex
CREATE INDEX "AnalysisRiskScore_userId_idx" ON "AnalysisRiskScore"("userId");

-- CreateIndex
CREATE INDEX "AnalysisRiskScore_reportId_idx" ON "AnalysisRiskScore"("reportId");

-- CreateIndex
CREATE INDEX "AnalysisRiskScore_overallRiskBand_idx" ON "AnalysisRiskScore"("overallRiskBand");

-- CreateIndex
CREATE INDEX "AnalysisRiskScore_generatedAt_idx" ON "AnalysisRiskScore"("generatedAt");
