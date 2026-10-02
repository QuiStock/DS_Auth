package com.quistock.auth.config;

import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

@Component
public class SqlReadinessCheck implements ApplicationRunner {
  private final JdbcTemplate jdbcTemplate;

  public SqlReadinessCheck(JdbcTemplate jdbcTemplate) {
    this.jdbcTemplate = jdbcTemplate;
  }

  @Override
  public void run(ApplicationArguments arguments) {
    jdbcTemplate.queryForList(
        "SELECT u.id, u.email, u.status::text AS status, u.password_hash, r.code, r.name "
            + "FROM user_account u JOIN role r ON r.id = u.role_id WHERE 1 = 0");
  }
}
