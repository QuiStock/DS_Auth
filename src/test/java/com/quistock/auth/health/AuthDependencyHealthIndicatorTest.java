package com.quistock.auth.health;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.quistock.auth.model.RefreshTokenDocument;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.sql.Statement;
import javax.sql.DataSource;
import org.bson.Document;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.SimpleTransactionStatus;
import org.springframework.transaction.support.TransactionTemplate;

class AuthDependencyHealthIndicatorTest {
  private final DataSource dataSource = mock(DataSource.class);
  private final MongoTemplate mongo = mock(MongoTemplate.class);
  private AuthDependencyHealthIndicator indicator;

  @BeforeEach
  void setup() throws SQLException {
    Connection connection = mock(Connection.class);
    Statement statement = mock(Statement.class);
    ResultSet rows = mock(ResultSet.class);
    when(dataSource.getConnection()).thenReturn(connection);
    when(connection.createStatement()).thenReturn(statement);
    when(statement.executeQuery(any(String.class))).thenReturn(rows);
    when(rows.getMetaData()).thenReturn(mock(ResultSetMetaData.class));
    when(mongo.executeCommand(any(Document.class)))
        .thenReturn(new Document("setName", "rs0").append("isWritablePrimary", true));
    PlatformTransactionManager manager = mock(PlatformTransactionManager.class);
    when(manager.getTransaction(any())).thenReturn(new SimpleTransactionStatus());
    indicator =
        new AuthDependencyHealthIndicator(
            dataSource, mongo, new TransactionTemplate(manager), 1000);
  }

  @AfterEach
  void cleanup() {
    indicator.shutdown();
  }

  @Test
  void requiresSqlAndMongoTransactionAccess() {
    assertThat(indicator.health().getStatus().getCode()).isEqualTo("UP");
  }

  @Test
  void reportsSqlConnectionFailure() throws SQLException {
    when(dataSource.getConnection()).thenThrow(new SQLException("unavailable"));
    assertThat(indicator.health().getStatus().getCode()).isEqualTo("DOWN");
  }

  @Test
  void rejectsStandaloneMongo() {
    when(mongo.executeCommand(any(Document.class)))
        .thenReturn(new Document("isWritablePrimary", true));
    assertThat(indicator.health().getStatus().getCode()).isEqualTo("DOWN");
  }

  @Test
  void rejectsUnavailablePrimary() {
    when(mongo.executeCommand(any(Document.class)))
        .thenReturn(new Document("setName", "rs0").append("isWritablePrimary", false));
    assertThat(indicator.health().getStatus().getCode()).isEqualTo("DOWN");
  }

  @Test
  void rejectsMongoTransactionReadFailure() {
    when(mongo.exists(any(Query.class), eq(RefreshTokenDocument.class)))
        .thenThrow(new DataAccessResourceFailureException("unavailable"));
    assertThat(indicator.health().getStatus().getCode()).isEqualTo("DOWN");
  }
}
