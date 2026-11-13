ALTER TABLE invitation_codes
  ADD COLUMN allows_username_choice BOOLEAN NOT NULL DEFAULT FALSE,
  ADD CONSTRAINT invitation_codes_username_choice_check
    CHECK (NOT allows_username_choice OR assigned_username IS NULL);
