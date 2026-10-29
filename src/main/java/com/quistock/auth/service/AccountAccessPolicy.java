package com.quistock.auth.service;

import com.quistock.auth.error.ApiExceptionFactory;
import com.quistock.auth.model.UserAccount;
import com.quistock.auth.repository.UserAccountRepository;
import java.util.Locale;
import java.util.Set;

public class AccountAccessPolicy {
  private static final Set<String> EMPLOYEE =
      Set.of("employee", "funcionario", "funcionário", "repositor");
  private static final Set<String> MANAGER = Set.of("manager", "gerente");
  private static final Set<String> REGIONAL = Set.of("regional manager", "gerente regional");
  private final UserAccountRepository users;

  public AccountAccessPolicy(UserAccountRepository users) {
    this.users = users;
  }

  public void requireAllowed(UserAccount account, String platform) {
    boolean employee = matches(EMPLOYEE, account);
    boolean manager = matches(MANAGER, account);
    boolean regional = matches(REGIONAL, account);
    if (!platformAllowed(platform, employee, regional)) {
      throw ApiExceptionFactory.forbiddenPlatform();
    }
    if (needsStore(platform, employee, manager) && !users.hasExactlyOneActiveStore(account.id())) {
      throw ApiExceptionFactory.noActiveStore();
    }
  }

  private boolean matches(Set<String> labels, UserAccount account) {
    return labels.contains(normalize(account.roleCode()))
        || labels.contains(normalize(account.roleName()));
  }

  private boolean platformAllowed(String platform, boolean employee, boolean regional) {
    return !("mobile".equals(platform) && regional) && !("website".equals(platform) && employee);
  }

  private boolean needsStore(String platform, boolean employee, boolean manager) {
    return "mobile".equals(platform) && (employee || manager);
  }

  private String normalize(String value) {
    return value == null
        ? ""
        : value.strip().toLowerCase(Locale.ROOT).replace('_', ' ').replace('-', ' ');
  }
}
