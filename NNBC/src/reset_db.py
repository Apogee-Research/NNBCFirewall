#!/usr/bin/env python3

import yaml
import psycopg2
import sys

CREATE_TABLE = '''
CREATE TABLE nnbc_clients (
addr INET PRIMARY KEY,
t1_score float4,
t2_score float4,
t2_access_multiplier float4,
t2_blocked BOOLEAN,
misbehaviors INT,
accesses INT,
connections INT)'''

config = sys.argv[1]
with open(config) as f:
    config = yaml.load(f)["database"]

with psycopg2.connect(**config) as conn:
    with conn.cursor() as cur:
        cur.execute("DROP TABLE IF EXISTS nnbc_clients")
        cur.execute(CREATE_TABLE)
