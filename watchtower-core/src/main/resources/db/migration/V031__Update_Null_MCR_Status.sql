ALTER TABLE pull_request_scans ALTER mcr_status DROP DEFAULT;
UPDATE pull_request_scans SET mcr_status=NULL WHERE mcr_status=0;