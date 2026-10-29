-- Run with psql as the database owner BEFORE deploying DS_Auth.
-- Example: psql --dbname="[POSTGRESQL_CONNECTION_URI]" -v auth_role=quistock_auth -f docs/mobile-store-eligibility.sql
-- The role must already exist. This grants no write privileges.
GRANT USAGE ON SCHEMA public TO :"auth_role";
GRANT SELECT (user_id, store_id, active) ON TABLE public.user_store TO :"auth_role";
GRANT SELECT (id, status) ON TABLE public.store TO :"auth_role";
