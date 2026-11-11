-- Bitbucket webhook uuid, captured on registration so unregister/re-register can find and
-- update the same hook instead of creating a duplicate (IMPROVEMENT_PLAN.md item 8, point 3).
-- Nullable: blank until a registration succeeds.
ALTER TABLE bb_cloud_integration_entity
    ADD COLUMN webhook_uuid varchar(255) DEFAULT NULL;

-- Every existing Bitbucket integration was created before self-registration existed, so its
-- register_state defaulted to NOT_SUPPORTED. Flip it to NOT_REGISTERED so the existing
-- Register/Unregister buttons (already built, see IMPROVEMENT_PLAN.md item 8) start rendering
-- for these rows without requiring a resave.
UPDATE integration_entity
SET register_state = 'NOT_REGISTERED'
WHERE register_state = 'NOT_SUPPORTED'
  AND integration_id IN (SELECT integration_id FROM bb_cloud_integration_entity);
