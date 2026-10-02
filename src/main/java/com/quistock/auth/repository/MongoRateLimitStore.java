package com.quistock.auth.repository;

import com.mongodb.DuplicateKeyException;
import com.quistock.auth.model.RateLimitCounter;
import java.time.Instant;
import org.springframework.data.mongodb.core.FindAndModifyOptions;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.data.mongodb.core.query.Update;
import org.springframework.stereotype.Repository;

@Repository
public class MongoRateLimitStore {
  private static final int MAX_UPSERT_ATTEMPTS = 3;
  private static final int LAST_UPSERT_ATTEMPT = MAX_UPSERT_ATTEMPTS - 1;
  private final MongoTemplate mongoTemplate;

  public MongoRateLimitStore(MongoTemplate mongoTemplate) {
    this.mongoTemplate = mongoTemplate;
  }

  public long increment(String id, Instant expiresAt) {
    Query query = Query.query(Criteria.where("id").is(id));
    Update update =
        new Update().inc("count", 1).setOnInsert("id", id).setOnInsert("expiresAt", expiresAt);
    FindAndModifyOptions options = FindAndModifyOptions.options().upsert(true).returnNew(true);

    for (int attempt = 0; attempt < MAX_UPSERT_ATTEMPTS; attempt++) {
      try {
        RateLimitCounter counter =
            mongoTemplate.findAndModify(query, update, options, RateLimitCounter.class);
        if (counter != null) {
          return counter.count();
        }
      } catch (DuplicateKeyException exception) {
        if (attempt == LAST_UPSERT_ATTEMPT) {
          throw exception;
        }
        options = FindAndModifyOptions.options().returnNew(true);
      }
    }
    throw new IllegalStateException("MongoDB did not return the updated rate-limit counter.");
  }
}
