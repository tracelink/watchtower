-- The embedded H2 browser console is no longer part of Watchtower. Remove its obsolete
-- privilege after first removing role assignments that reference it.
DELETE FROM role_privilege
WHERE privilege_id IN (
  SELECT privilege_id FROM privileges WHERE name = 'Database Access'
);

DELETE FROM privileges WHERE name = 'Database Access';
