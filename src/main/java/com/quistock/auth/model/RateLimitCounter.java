package com.quistock.auth.model;

import java.time.Instant;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.mapping.Field;

@Document("auth_rate_limit")
public record RateLimitCounter(@Id String id, long count, @Field("expires_at") Instant expiresAt) {}
