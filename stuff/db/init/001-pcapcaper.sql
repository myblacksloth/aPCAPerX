-- PostgreSQL initialization hook for PCAPCaper.
-- The application creates and migrates auth tables on startup. This file is
-- intentionally minimal so Docker's official postgres image has an init folder
-- ready for future database-level extensions, roles, or seed data.

CREATE EXTENSION IF NOT EXISTS pgcrypto;
