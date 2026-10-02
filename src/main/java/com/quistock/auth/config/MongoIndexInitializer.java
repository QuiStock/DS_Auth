package com.quistock.auth.config;

import com.quistock.auth.model.RateLimitCounter;
import com.quistock.auth.model.RefreshTokenDocument;
import java.time.Duration;
import org.bson.Document;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.data.domain.Sort;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.index.Index;
import org.springframework.stereotype.Component;

@Component
public class MongoIndexInitializer implements ApplicationRunner {
  private final MongoTemplate mongoTemplate;

  public MongoIndexInitializer(MongoTemplate mongoTemplate) {
    this.mongoTemplate = mongoTemplate;
  }

  @Override
  public void run(ApplicationArguments arguments) {
    Document hello = mongoTemplate.executeCommand(new Document("hello", 1));
    if (hello == null || !hello.containsKey("setName")) {
      throw new IllegalStateException("MongoDB must be configured as a replica set.");
    }
    mongoTemplate
        .indexOps(RefreshTokenDocument.class)
        .ensureIndex(
            new Index()
                .on("tokenHash", Sort.Direction.ASC)
                .unique()
                .named("uq_refresh_token_hash"));
    mongoTemplate
        .indexOps(RefreshTokenDocument.class)
        .ensureIndex(new Index().on("familyId", Sort.Direction.ASC).named("ix_refresh_family"));
    mongoTemplate
        .indexOps(RefreshTokenDocument.class)
        .ensureIndex(new Index().on("expiresAt", Sort.Direction.ASC).expire(Duration.ZERO));
    mongoTemplate
        .indexOps(RateLimitCounter.class)
        .ensureIndex(new Index().on("expiresAt", Sort.Direction.ASC).expire(Duration.ZERO));
  }
}
