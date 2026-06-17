# NIRAVAN Master Roadmap Implementation Checklist

## Backend Extensions
- [x] Add `affected_citizens`, `affected_services`, `affected_departments`, and `estimated_recovery_time` to `IncidentModel` & `CaseModel`
- [x] Create `ServiceAvailabilityModel` table
- [x] Seed database with public-sector presets and service availability rows
- [x] Implement new API endpoints:
  - [x] `/api/v1/knowledge/ontology`
  - [x] `/api/v1/knowledge/base`
  - [x] `/api/v1/intelligence/statewide-exchange`
  - [x] `/api/v1/mitigation/crisis-lockdown`
  - [x] `/api/v1/service-availability`
- [x] Integrate host-level impact mapping in `backend/correlation_engine.py`
- [x] Update `/api/v1/copilot` endpoint with bilingual friendly advisor logic

## Frontend Upgrades
- [x] Add Citizen Impact dashboard widget in `index.html`
- [x] Add Service Availability status indicators in `index.html`
- [x] Add Red Crisis Lockdown button & Javascript functionality in `index.html`
- [x] Map OS HUD blueprint layer clicks to call the new ontology/knowledge APIs and display info in the HUD modal

## Testing & Verification
- [x] Create automated test suite `backend/test_roadmap_additions.py`
- [x] Delete SQLite DB to force re-creation and re-seed
- [x] Run backend tests (`pytest`)
- [x] Run Playwright tests
