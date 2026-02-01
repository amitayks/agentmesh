## MODIFIED Requirements

### Requirement: Skill manifest version
The skill.json manifest SHALL declare the correct protocol version.

#### Scenario: Version matches protocol
- **WHEN** skill.json is read
- **THEN** the "version" field SHALL be "0.2.0"
- **AND** match the agentmesh/0.2 protocol version

#### Scenario: Version update on protocol change
- **WHEN** the protocol version changes
- **THEN** skill.json version SHALL be updated to match

### Requirement: mesh_dashboard browser launch
The mesh_dashboard command SHALL open the dashboard in the user's default browser.

#### Scenario: Dashboard opens in browser
- **WHEN** mesh_dashboard command is executed
- **THEN** the system SHALL call webbrowser.open() with the dashboard URL
- **AND** log "Opening dashboard at http://localhost:7777"

#### Scenario: Dashboard URL configurable
- **WHEN** dashboard_port is configured
- **THEN** mesh_dashboard SHALL use http://localhost:<dashboard_port>

#### Scenario: Browser launch failure handled
- **WHEN** webbrowser.open() fails
- **THEN** the system SHALL log an error
- **AND** print the URL for manual access

### Requirement: Skill dependencies updated
The skill manifest SHALL declare all required dependencies.

#### Scenario: python-olm in dependencies
- **WHEN** reading skill.json python_requirements
- **THEN** "python-olm>=3.2.0" SHALL be included

#### Scenario: jsonschema in dependencies
- **WHEN** reading skill.json python_requirements
- **THEN** "jsonschema>=4.0.0" SHALL be included

### Requirement: Skill metadata accuracy
The skill manifest SHALL contain accurate metadata.

#### Scenario: Homepage URL correct
- **WHEN** reading skill.json
- **THEN** "homepage" SHALL point to valid repository URL

#### Scenario: Description updated
- **WHEN** reading skill.json
- **THEN** "description" SHALL mention E2EE and KNOCK protocol
