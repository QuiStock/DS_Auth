package com.quistock.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.quistock.auth.error.ApiException;
import com.quistock.auth.model.UserAccount;
import com.quistock.auth.repository.UserAccountRepository;
import com.quistock.auth.service.AccountAccessPolicy;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.dao.DataAccessResourceFailureException;

class AccountAccessPolicyTests {
  private final UserAccountRepository users = mock(UserAccountRepository.class);
  private final AccountAccessPolicy policy = new AccountAccessPolicy(users);

  @ParameterizedTest
  @ValueSource(strings = {"EMPLOYEE", "MANAGER", "REPOSITOR", "FUNCIONARIO", "GERENTE"})
  void mobileStoreRolesRequireExactlyOneActiveStore(String role) {
    UserAccount account = account(role);
    assertThatThrownBy(() -> policy.requireAllowed(account, "mobile"))
        .isInstanceOfSatisfying(
            ApiException.class, error -> assertThat(error.code()).isEqualTo("no_active_store"));
    when(users.hasExactlyOneActiveStore(101L)).thenReturn(true);
    policy.requireAllowed(account, "mobile");
    verify(users, org.mockito.Mockito.times(2)).hasExactlyOneActiveStore(101L);
  }

  @ParameterizedTest
  @ValueSource(strings = {"REGIONAL_MANAGER", "GERENTE_REGIONAL"})
  void regionalManagersUseWebsiteWithoutAStore(String role) {
    policy.requireAllowed(account(role), "website");
    assertThatThrownBy(() -> policy.requireAllowed(account(role), "mobile"))
        .isInstanceOfSatisfying(
            ApiException.class,
            error -> assertThat(error.code()).isEqualTo("platform_not_allowed"));
    verifyNoInteractions(users);
  }

  @Test
  void websiteManagersDoNotRequireStoreAndEmployeesRemainForbidden() {
    policy.requireAllowed(account("MANAGER"), "website");
    assertThatThrownBy(() -> policy.requireAllowed(account("EMPLOYEE"), "website"))
        .isInstanceOf(ApiException.class);
    verifyNoInteractions(users);
  }

  @Test
  void databaseFailureDoesNotBecomeMissingStore() {
    when(users.hasExactlyOneActiveStore(101L))
        .thenThrow(new DataAccessResourceFailureException("unavailable"));
    assertThatThrownBy(() -> policy.requireAllowed(account("EMPLOYEE"), "mobile"))
        .isInstanceOf(DataAccessResourceFailureException.class);
  }

  private UserAccount account(String role) {
    return new UserAccount(101L, "fixture@example.test", "ACTIVE", "fixture", role, role);
  }
}
