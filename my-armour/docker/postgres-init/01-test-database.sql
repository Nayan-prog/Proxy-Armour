-- Runs once, when the postgres volume is first created.
-- Throwaway database for `scripts/stack.py test` (tables are dropped/recreated by the tests).
CREATE DATABASE armour_test;
