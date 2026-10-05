package com.quistock.auth.health;

import com.quistock.auth.model.RefreshTokenDocument;
import java.time.Duration;
import javax.sql.DataSource;
import org.bson.Document;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionTemplate;

@Component("dependenciesHealthIndicator")
public class AuthDependencyHealthIndicator extends DependencyHealthIndicator {
  private final JdbcTemplate sql;
  private final MongoTemplate mongo;
  private final TransactionTemplate transactions;

  public AuthDependencyHealthIndicator(
      DataSource dataSource,
      MongoTemplate mongo,
      @Qualifier("mongoTransactionTemplate") TransactionTemplate transactionTemplate,
      @Value("${app.health.timeout-ms:4000}") long timeoutMs) {
    super(timeoutMs);
    this.sql = new JdbcTemplate(dataSource);
    this.sql.setQueryTimeout(2);
    this.mongo = mongo;
    this.transactions = new TransactionTemplate(transactionTemplate.getTransactionManager());
    this.transactions.setReadOnly(true);
    this.transactions.setTimeout(2);
  }

  @Override
  protected boolean dependenciesAvailable() {
    sql.queryForList(
        "SELECT u.id, u.email, u.status::text AS status, u.password_hash, r.code, r.name "
            + "FROM user_account u JOIN role r ON r.id = u.role_id WHERE 1 = 0");
    var hello = mongo.executeCommand(new Document("hello", 1));
    if (!hello.containsKey("setName") || !Boolean.TRUE.equals(hello.get("isWritablePrimary"))) {
      return false;
    }
    return Boolean.TRUE.equals(
        transactions.execute(
            status -> {
              mongo.exists(new Query().maxTime(Duration.ofSeconds(2)), RefreshTokenDocument.class);
              return true;
            }));
  }
}
