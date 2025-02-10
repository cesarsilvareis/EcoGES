SET client_min_messages TO WARNING;
SET client_encoding TO 'UTF8';

DROP TABLE IF EXISTS household_appliance, solar_panel, monthly_invoice, client, secret_key CASCADE;
DROP SEQUENCE IF EXISTS client_id_seq CASCADE;

CREATE SEQUENCE client_id_seq;

CREATE TABLE secret_key (
    department_id INTEGER NOT NULL,
    department_key bytea NOT NULL,
    
    UNIQUE(department_key),
    PRIMARY KEY (department_id)
);

CREATE TABLE client (
    id INTEGER NOT NULL DEFAULT nextval('client_id_seq'),
    name VARCHAR(40) CHECK(LENGTH(name) >= 3),
    email VARCHAR (30) CHECK(LENGTH(email) >= 5),
    
    pass bytea NOT NULL,
    perms bytea NOT NULL,
    
    bank_account_id bytea NOT NULL,
    
    address bytea NOT NULL,
    phone_number bytea NOT NULL,

    UNIQUE (email),
    UNIQUE (id, bank_account_id),
    UNIQUE (id, phone_number),
    PRIMARY KEY (id)
);

CREATE TABLE household_appliance (
    id INTEGER NOT NULL,
    name VARCHAR(40) CHECK(LENGTH(name) >= 2),
    energy_consumption FLOAT,
    uptime INTERVAL,
    active BOOLEAN,
    last_check TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT 'now',
    client_id INTEGER NOT NULL,

    PRIMARY KEY (id),
    FOREIGN KEY (client_id) REFERENCES client(id)
);

CREATE TABLE solar_panel (
    id INTEGER NOT NULL,
    name VARCHAR(40) CHECK(LENGTH(name) >= 2),
    energy_production_rate FLOAT,
    energy_produced FLOAT,
    uptime INTERVAL,
    active BOOLEAN,
    last_check TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT 'now',
    client_id INTEGER NOT NULL,

    PRIMARY KEY (id),
    FOREIGN KEY (client_id) REFERENCES client(id)
);

CREATE TABLE monthly_invoice (
    id INTEGER NOT NULL,
    month INTEGER NOT NULL,
    consumed_energy FLOAT,
    plan bytea,
    taxes bytea,

    PRIMARY KEY (id),
    FOREIGN KEY (id) REFERENCES client(id)
);

---------------------------------------------------------------------------------------------------

GRANT SELECT, INSERT, UPDATE, DELETE ON household_appliance, solar_panel TO appserver;
GRANT SELECT, INSERT, UPDATE ON client, monthly_invoice, secret_key TO appserver;
GRANT SELECT, UPDATE ON client_id_seq TO appserver;

---------------------------------------------------------------------------------------------------
