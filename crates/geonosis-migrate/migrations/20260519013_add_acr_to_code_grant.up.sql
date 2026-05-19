--- kind: expand
--- compatible-server-min: 0.1.0
--- compatible-server-max: 0.1.x

-- v0.1.x: Thread ACR (Authentication Context Class Reference) from the
-- authorize flow through the code grant to the token mint path. Nullable
-- because pre-existing grants and non-ACR-aware clients omit it.
ALTER TABLE code_grant ADD COLUMN acr TEXT;
