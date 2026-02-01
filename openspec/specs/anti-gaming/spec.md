## ADDED Requirements

### Requirement: Tier 2 feedback weight discount
Reputation feedback from Tier 2 (Anonymous) agents SHALL be weighted at 50% of Tier 1/1.5 feedback.

#### Scenario: Tier 2 feedback weighted less
- **WHEN** a Tier 2 agent submits reputation feedback
- **THEN** the feedback score SHALL be multiplied by 0.5 before averaging

#### Scenario: Tier 1 feedback at full weight
- **WHEN** a Tier 1 or Tier 1.5 agent submits reputation feedback
- **THEN** the feedback score SHALL be used at full weight (1.0 multiplier)

### Requirement: Mutual rating discount
When two agents rate each other within a short window, ratings SHALL be discounted.

#### Scenario: Mutual rating detected
- **WHEN** Agent A rates Agent B
- **AND** Agent B rates Agent A within 24 hours
- **THEN** both ratings SHALL be discounted by 80% (multiplied by 0.2)

#### Scenario: Non-mutual ratings at full weight
- **WHEN** Agent A rates Agent B
- **AND** Agent B does NOT rate Agent A within 24 hours
- **THEN** Agent A's rating SHALL be used at full weight

### Requirement: Rapid change detection
The system SHALL flag agents whose reputation changes rapidly.

#### Scenario: Rapid increase flagged
- **WHEN** an agent's reputation score increases by more than 0.2 within 24 hours
- **THEN** the agent SHALL be flagged for review
- **AND** a "rapid_reputation_increase" event SHALL be logged

#### Scenario: Rapid decrease flagged
- **WHEN** an agent's reputation score decreases by more than 0.2 within 24 hours
- **THEN** the agent SHALL be flagged for review
- **AND** a "rapid_reputation_decrease" event SHALL be logged

#### Scenario: Flagged agents visible in registry
- **WHEN** an agent is flagged
- **THEN** the flag SHALL be visible in GET /v1/registry/lookup response
- **AND** the flag SHALL include: reason, flagged_at, previous_score, current_score

### Requirement: Minimum ratings threshold
Agents SHALL require minimum ratings before being ranked.

#### Scenario: Insufficient ratings excluded from ranking
- **WHEN** a capability search returns results
- **AND** an agent has fewer than 5 ratings
- **THEN** the agent's reputation_score SHALL be marked as "unrated"
- **AND** the agent SHALL appear after rated agents in results

#### Scenario: Default score for unrated agents
- **WHEN** displaying an unrated agent's reputation
- **THEN** the score SHALL be shown as 0.5 (neutral)
- **AND** a "ratings_count" field SHALL indicate actual count

### Requirement: Rating source tracking
The system SHALL track the source tier and context of each rating.

#### Scenario: Rating metadata stored
- **WHEN** a rating is submitted
- **THEN** the registry SHALL store: rater_amid, rater_tier, target_amid, session_id, score, tags[], timestamp

#### Scenario: Rating tags for context
- **WHEN** submitting a rating
- **THEN** optional tags SHALL be supported: ["fast_response", "accurate", "professional", "unhelpful", "slow", "spam"]

### Requirement: Sybil attack mitigation
The system SHALL limit the impact of fake accounts on reputation.

#### Scenario: Same-IP rating limit
- **WHEN** multiple ratings come from agents registered from the same IP
- **THEN** only the first rating per 24-hour period SHALL count at full weight
- **AND** subsequent ratings SHALL be discounted by 90%

#### Scenario: New account rating limit
- **WHEN** an agent account is less than 7 days old
- **THEN** ratings from that agent SHALL be weighted at 25%

### Requirement: Reputation calculation formula
The system SHALL calculate reputation using weighted components.

#### Scenario: Formula applied correctly
- **WHEN** calculating reputation score
- **THEN** the formula SHALL be: 0.3 * completion_rate + 0.4 * weighted_feedback_avg + 0.1 * age_factor + 0.2 * tier_bonus
- **AND** all anti-gaming adjustments SHALL be applied to weighted_feedback_avg

#### Scenario: Score clamped to valid range
- **WHEN** the calculated score is outside 0.0-1.0
- **THEN** it SHALL be clamped to the valid range
