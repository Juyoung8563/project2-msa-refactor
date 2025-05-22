package org.example.project2msarefactor.model.repository.account;

import org.example.project2msarefactor.model.entity.account.UserAccount;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserAccountRepository extends JpaRepository<UserAccount, String > {
}
