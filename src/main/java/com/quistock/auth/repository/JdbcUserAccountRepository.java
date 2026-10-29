package com.quistock.auth.repository;

import com.quistock.auth.model.UserAccount;
import java.util.List;
import java.util.Optional;
import org.springframework.dao.IncorrectResultSizeDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

@Repository
public class JdbcUserAccountRepository implements UserAccountRepository {
  private static final int SINGLE_ACCOUNT_MATCH = 1;
  private static final String SELECT_COLUMNS =
      "SELECT u.id, u.email, u.status::text AS status, u.password_hash, "
          + "r.code AS role_code, r.name AS role_name "
          + "FROM user_account u JOIN role r ON r.id = u.role_id ";
  private final JdbcTemplate jdbcTemplate;

  public JdbcUserAccountRepository(JdbcTemplate jdbcTemplate) {
    this.jdbcTemplate = jdbcTemplate;
  }

  @Override
  public Optional<UserAccount> findByNormalizedEmail(String normalizedEmail) {
    List<UserAccount> accounts =
        jdbcTemplate.query(
            SELECT_COLUMNS + "WHERE lower(btrim(email)) = ?",
            (resultSet, rowNumber) ->
                new UserAccount(
                    resultSet.getLong("id"),
                    resultSet.getString("email"),
                    resultSet.getString("status"),
                    resultSet.getString("password_hash"),
                    resultSet.getString("role_code"),
                    resultSet.getString("role_name")),
            normalizedEmail);
    if (accounts.size() > SINGLE_ACCOUNT_MATCH) {
      throw new IncorrectResultSizeDataAccessException(1, accounts.size());
    }
    return accounts.stream().findFirst();
  }

  @Override
  public Optional<UserAccount> findById(long id) {
    List<UserAccount> accounts =
        jdbcTemplate.query(
            SELECT_COLUMNS + "WHERE u.id = ?",
            (resultSet, rowNumber) ->
                new UserAccount(
                    resultSet.getLong("id"),
                    resultSet.getString("email"),
                    resultSet.getString("status"),
                    resultSet.getString("password_hash"),
                    resultSet.getString("role_code"),
                    resultSet.getString("role_name")),
            id);
    return accounts.stream().findFirst();
  }
}
