## ADDED Requirements

### Requirement: Reputation score calculation
The registry SHALL calculate reputation scores using the formula: `reputation = (0.3 * completion_rate) + (0.4 * avg_peer_feedback) + (0.1 * age_factor) + (0.2 * tier_bonus)`.

#### Scenario: New agent default score
- **WHEN** Tier 2 agent registers
- **THEN** reputation_score is set to 0.5

#### Scenario: Tier bonus applied
- **WHEN** Tier 1 agent registers
- **THEN** starting reputation is 0.6 (tier_bonus = 0.5)
- **AND** Tier 1.5 starts at 0.7 (tier_bonus = 1.0)

#### Scenario: Score recalculated on feedback
- **WHEN** new peer feedback is submitted
- **THEN** registry recalculates agent's reputation
- **AND** updated score is reflected in lookups

### Requirement: Peer feedback submission
Agents SHALL submit reputation feedback after session close. Feedback includes score (0.0-1.0), optional tags, and session_id.

#### Scenario: Feedback submitted successfully
- **WHEN** agent submits valid reputation feedback with score 0.8
- **THEN** registry records feedback
- **AND** returns success response

#### Scenario: Invalid score rejected
- **WHEN** agent submits feedback with score > 1.0 or < 0.0
- **THEN** registry returns 400 with error "invalid_score"

#### Scenario: Feedback requires session
- **WHEN** agent submits feedback without valid session_id
- **THEN** registry returns 400 with error "invalid_session"

### Requirement: Completion rate tracking
Registry SHALL track session completion rate per agent. Sessions ending with reason "completed" count as successful.

#### Scenario: Successful session recorded
- **WHEN** session closes with reason "completed"
- **THEN** registry increments agent's completed_sessions count

#### Scenario: Failed session recorded
- **WHEN** session closes with reason "error" or "timeout"
- **THEN** registry increments agent's failed_sessions count

#### Scenario: Completion rate calculated
- **WHEN** agent has 80 completed and 20 failed sessions
- **THEN** completion_rate = 0.8

### Requirement: Age factor calculation
Age factor SHALL increase with account age, capping at 1.0 after 365 days. Formula: `min(1.0, days_since_creation / 365)`.

#### Scenario: New agent age factor
- **WHEN** agent registered today
- **THEN** age_factor = 0.0

#### Scenario: One year old agent
- **WHEN** agent registered 365+ days ago
- **THEN** age_factor = 1.0 (capped)

### Requirement: Anti-gaming measures
Registry SHALL implement anti-gaming protections: Tier 2 feedback weighted at 50%, mutual-only rating pairs discounted 80%, rapid changes flagged.

#### Scenario: Tier 2 feedback weighted
- **WHEN** Tier 2 agent submits feedback
- **THEN** feedback weight is 0.5 (vs 1.0 for Tier 1/1.5)

#### Scenario: Mutual rating discount
- **WHEN** agents A and B only rate each other (no other ratings)
- **THEN** their mutual ratings are weighted at 0.2

#### Scenario: Rapid change flagged
- **WHEN** agent's score changes > 0.1 in 24 hours
- **THEN** registry flags agent for review
- **AND** score changes are temporarily capped

### Requirement: Reputation in KNOCK messages
KNOCK messages SHALL include sender's reputation_score. Receivers use this for policy evaluation (min_reputation check).

#### Scenario: Reputation included in KNOCK
- **WHEN** agent sends KNOCK
- **THEN** from.reputation_score is populated from registry

#### Scenario: Reputation below threshold rejected
- **WHEN** KNOCK has reputation_score 0.3 and policy.min_reputation is 0.5
- **THEN** KNOCK is rejected with reason "low_reputation"

### Requirement: Reputation tags
Peer feedback MAY include tags describing interaction quality. Standard tags: fast, slow, accurate, inaccurate, helpful, unresponsive.

#### Scenario: Tags included in feedback
- **WHEN** agent submits feedback with tags ["fast", "accurate"]
- **THEN** registry stores tags with feedback

#### Scenario: Tag aggregation
- **WHEN** agent has received 10+ feedbacks
- **THEN** lookup response includes top 3 most common tags

### Requirement: Minimum ratings threshold
Agents SHALL require minimum 5 ratings from distinct peers before reputation affects discovery ranking.

#### Scenario: Below minimum threshold
- **WHEN** agent has 3 ratings
- **THEN** discovery ranking uses default score (0.5)
- **AND** lookup indicates "reputation_provisional": true

#### Scenario: Above minimum threshold
- **WHEN** agent has 5+ ratings from distinct peers
- **THEN** calculated reputation is used for ranking
