package com.quistock.auth.repository;

import com.quistock.auth.model.RefreshTokenDocument;
import java.time.Instant;
import java.util.Optional;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.data.mongodb.core.query.Update;
import org.springframework.stereotype.Repository;

@Repository
public class MongoRefreshTokenStore {
  private static final String STATE_FIELD = "state";
  private static final String ACTIVE = "ACTIVE";
  private static final String CONSUMED = "CONSUMED";
  private static final String REVOKED = "REVOKED";
  private final MongoTemplate mongoTemplate;

  public MongoRefreshTokenStore(MongoTemplate mongoTemplate) {
    this.mongoTemplate = mongoTemplate;
  }

  public Optional<RefreshTokenDocument> findByTokenHash(String tokenHash) {
    Query query = Query.query(Criteria.where("tokenHash").is(tokenHash));
    return Optional.ofNullable(mongoTemplate.findOne(query, RefreshTokenDocument.class));
  }

  public void insert(RefreshTokenDocument token) {
    mongoTemplate.insert(token);
  }

  public boolean consumeActive(String id, Instant now, Instant consumedAt, String successorId) {
    Query query =
        Query.query(
            Criteria.where("id").is(id).and(STATE_FIELD).is(ACTIVE).and("expiresAt").gt(now));
    Update update =
        new Update()
            .set(STATE_FIELD, CONSUMED)
            .set("consumedAt", consumedAt)
            .set("replacedById", successorId);
    return mongoTemplate.updateFirst(query, update, RefreshTokenDocument.class).getModifiedCount()
        == 1;
  }

  public void revokeFamily(String familyId, Instant revokedAt) {
    Query query = Query.query(Criteria.where("familyId").is(familyId).and(STATE_FIELD).ne(REVOKED));
    Update update = new Update().set(STATE_FIELD, REVOKED).set("revokedAt", revokedAt);
    mongoTemplate.updateMulti(query, update, RefreshTokenDocument.class);
  }
}
