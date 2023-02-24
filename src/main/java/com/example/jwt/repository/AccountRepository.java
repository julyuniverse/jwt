package com.example.jwt.repository;

import com.example.jwt.entity.Account;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

/**
 * @author Lee Taesung
 * @since 2023/02/23
 */
public interface AccountRepository extends JpaRepository<Account, Long> {
    Optional<Account> findByEmail(String email);

    boolean existsByEmail(String email); // 중복 체크
}