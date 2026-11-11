-- Who first saw an AI opinion about a finding (a stored assessment or a chat answer), so blind
-- agreement counts only judgments made before the person saw any AI opinion. No source code is kept.
CREATE TABLE finding_ai_exposure (
 occurrence_key CHAR(64) NOT NULL,
 viewer VARCHAR(255) NOT NULL,
 source VARCHAR(16) NOT NULL,
 first_seen_at BIGINT NOT NULL,
 PRIMARY KEY (occurrence_key, viewer)
);
