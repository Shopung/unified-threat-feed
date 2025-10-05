# Unified Threat Feed (UTF)

A centralized, automated aggregator of public threat feeds — built for use with KQL queries and SIEM ingestion.

## Features
- Fetches multiple open-source threat intelligence feeds
- Normalizes IoCs into a unified format
- Automatically updates every 6 hours via GitHub Actions
- Outputs chunked JSON feeds (under 100MB each)

## Structure
See `/ingestion`, `/data_sources`, and `/kql` for modular logic.

## Next Steps
- Phase 2: Implement true normalization and deduplication
- Phase 3: KQL ingestion and query optimization
