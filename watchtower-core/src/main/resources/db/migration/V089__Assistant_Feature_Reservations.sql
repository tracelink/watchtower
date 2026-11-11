-- Which AI feature slice a reservation also charged; NULL for chat, so refunds reach the right bucket.
ALTER TABLE assistant_request_reservations ADD COLUMN feature VARCHAR(32) NULL;
