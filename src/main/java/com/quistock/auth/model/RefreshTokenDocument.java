package com.quistock.auth.model;

import java.time.Instant;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.mapping.Field;

@Document("refresh_token")
public record RefreshTokenDocument(
    @Id String id,
    @Field("family_id") String familyId,
    @Field("user_account_id") long userAccountId,
    @Field("token_hash") String tokenHash,
    String state,
    @Field("created_at") Instant createdAt,
    @Field("expires_at") Instant expiresAt,
    @Field("consumed_at") Instant consumedAt,
    @Field("revoked_at") Instant revokedAt,
    @Field("replaced_by_id") String replacedById) {}
