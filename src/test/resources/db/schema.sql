CREATE TYPE user_status AS ENUM ('ACTIVE', 'INACTIVE');

CREATE TABLE user_account (
    id BIGINT PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    status user_status NOT NULL,
    password_hash VARCHAR(255) NOT NULL
);
