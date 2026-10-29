CREATE TYPE user_status AS ENUM ('ACTIVE', 'INACTIVE');

CREATE TABLE role (
    id BIGINT PRIMARY KEY,
    code VARCHAR(50) NOT NULL UNIQUE,
    name VARCHAR(100) NOT NULL UNIQUE
);

CREATE TABLE user_account (
    id BIGINT PRIMARY KEY,
    role_id BIGINT NOT NULL REFERENCES role (id),
    email VARCHAR(255) NOT NULL UNIQUE,
    status user_status NOT NULL,
    password_hash VARCHAR(255) NOT NULL
);
