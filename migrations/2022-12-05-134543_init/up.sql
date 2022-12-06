-- Your SQL goes here

CREATE TABLE nodes (
    hash BYTEA PRIMARY KEY NOT NULL CHECK (length(hash) = 48),
    metadata BYTEA NOT NULL,
    metadata_hash BYTEA NOT NULL CHECK (length(metadata_hash) = 48),
    parent_hash BYTEA REFERENCES nodes(hash) -- length constriant implicit 
);

CREATE TABLE users (
    id INTEGER PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    pake_verify TEXT NOT NULL,
    top_hash BYTEA REFERENCES nodes(hash) NOT NULL CHECK (length(top_hash) = 48)
);
