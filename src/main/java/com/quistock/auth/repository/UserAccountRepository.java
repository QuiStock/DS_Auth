package com.quistock.auth.repository;

import com.quistock.auth.model.UserAccount;
import java.util.Optional;

public interface UserAccountRepository {
  Optional<UserAccount> findByNormalizedEmail(String normalizedEmail);

  Optional<UserAccount> findById(long id);
}
