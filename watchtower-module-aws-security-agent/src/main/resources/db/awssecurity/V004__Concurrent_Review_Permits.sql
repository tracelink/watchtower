-- Row 1 remains the serialization lock and the existing in-flight review keeps its slot.
INSERT INTO aws_security_permit (id) VALUES (2), (3), (4), (5);
