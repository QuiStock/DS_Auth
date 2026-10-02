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
        "SELECT id, email, status::text AS status, password_hash FROM user_account WHERE 1 = 0");
  }
}
