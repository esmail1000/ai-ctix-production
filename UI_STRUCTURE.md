# Ai CTIX - UI Structure

## Pages Overview (خريطة الموقع)

### 1. **Home** (`/`)
- Hero section with search/upload/investigate
- Latest IOCs, CVEs, and Reports
- Quick actions (Browse, Upload, View Graph)
- Quick statistics

### 2. **Dashboard** (`/dashboard`)
- KPIs: Total IOCs, New 24h, High Confidence, Exploited CVEs
- Trends: IOCs over time (7 days), Top sources
- Top Tags visualization
- Top Risky IOCs list
- Recent Activity log
- Feed Health status

### 3. **Analyzer** (`/analyzer`) (Core Run Page)
- User inputs a **Threat Report** via *Paste Text* or *Upload File*
- Run settings:
  - **Quick Scan** vs **Deep Analysis**
  - **Strictness** slider to reduce *false positives*
- On **Run**, stores the pipeline output (demo uses browser sessionStorage) then navigates to Results
- Core principle shown in UI:
  - **The sentence is treated as the fundamental unit of understanding**

### 4. **Results – Core Intelligence Pipeline** (`/results`)
- Summary cards (total indicators + type breakdown)
- Pipeline steps:
  - **Normalize** (text cleaning & normalization)
  - **Segment** (sentence/section segmentation with stable indices)
  - **Extract** (indicator extraction scored by Strictness)
- Findings table (indicator, type, confidence, evidence sentenceIndex)
- Right panel: Selected finding with sentence-level evidence + context window

### 5. **IOCs** (`/iocs`)
#### List View:
- Search bar with type:value support
- Filters: Type, Tags, Confidence range
- Bulk actions (tag, delete, export)
- Table with all IOC details

#### Detail View (`/iocs/[id]`):
- Overview with score, confidence, severity
- Timeline of sightings
- Enrichment data (ASN, geo, passive DNS)
- MITRE ATT&CK mapping
- Related entities
- Actions panel

#### Add IOC (`/iocs/new`):
- Manual IOC entry form (demo UI)

### 6. **MITRE** (`/mitre`)
- List view with tactic filter
- Matrix view (ATT&CK style)
- Technique details panel:
  - Description
  - Linked IOCs, Reports, Actors
  - Frequency/trend data
  - Actions (View IOCs, View Reports, View in Graph)

### 7. **Correlations Graph** (`/graph`)
- Interactive graph visualization (placeholder for Cytoscape.js/D3)
- Left panel: Filters (node types, min score, time range)
- Center: Graph canvas with nodes and edges
- Right panel: Selected node details + expand neighbors
- Export options (Save view, Export JSON/PDF)

### 8. **Export** (`/export`)
- Export type selection (Investigation, IOC, Graph, Report)
- Resource selection
- Format selection (JSON, PDF, CSV, STIX 2.1)
- Format-specific options (PDF: include details/graph)
- Export preview and recent exports

### 9. **Reports** (`/reports`)
- Demo report library
- Report detail page (`/reports/[id]`)
- CTA to run Analyzer on new reports

### 10. **Vulnerabilities** (`/vulnerabilities`)
- Demo CVE explorer
- CVE detail page (`/vulnerabilities/[cve]`)
- If an Analyzer run exists, show sentenceIndex mentions from the latest analyzed report

## Navigation Component

Sticky navigation bar with:
- Home, Dashboard, **Analyzer**, Results, IOCs, MITRE, Graph, Export
- Mobile-responsive menu
- Active page highlighting
- Icons for each page

## Design System

- **Theme**: Dark mode (default)
- **Colors**:
  - Primary: Blue (#3B82F6)
  - Success: Green (#10B981)
  - Warning: Orange/Yellow (#F59E0B)
  - Danger: Red (#EF4444)
  - Purple: Purple (#9333EA)
- **Typography**: Inter font family
- **Layout**: Max-width containers with responsive grids
- **Components**: Reusable cards, tables, modals

## Key Features Implemented

- Responsive navigation
- Analyzer (core run page)
- Results – Core Intelligence Pipeline (Normalize -> Segment -> Extract)
- Home, Dashboard, IOCs, MITRE, Graph, Export
- Reports and Vulnerabilities demo routes (no 404s from Home links)
- IOC list and detail views
- Search and filtering
- Dashboard with charts (using Recharts)
- MITRE ATT&CK matrix and list views
- Graph visualization structure (ready for integration)
- Export functionality UI
- Dark mode design
- Arabic/RTL support ready (in CSS)

## Next Steps for Integration

1. **API Integration**: Connect all pages to FastAPI backend
2. **Graph Visualization**: Integrate Cytoscape.js or D3.js for interactive graph
3. **State Management**: Add React Query or Zustand for data fetching
4. **Authentication**: Add login/logout UI components
5. **Form Handling**: Add forms for creating/editing IOCs, reports
6. **File Upload**: Implement CSV/JSON upload functionality
7. **PDF Generation**: Integrate PDF export library (Playwright/WeasyPrint)

## Running the UI

```bash
npm install
npm run dev
```

Access at: http://localhost:3000
