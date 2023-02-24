package com.example.jwt.service;

import com.example.jwt.config.exception.CustomException;
import com.example.jwt.config.exception.ErrorCode;
import com.example.jwt.entity.Account;
import com.example.jwt.repository.AccountRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

/**
 * @author Lee Taesung
 * @since 2023/02/24
 */
@Service
@RequiredArgsConstructor
public class AccountService {
    private final AccountRepository accountRepository;

    public Account findByEmail(String email) {
        return accountRepository.findByEmail(email).orElseThrow(() -> new CustomException(ErrorCode.ACCOUNT_NOT_FOUND));
    }

    public com.example.jwt.dto.account.Account setAccountResponse(Account account) {
        return com.example.jwt.dto.account.Account.builder()
                .accountId(account.getAccountId())
                .email(account.getEmail())
                .role(String.valueOf(account.getAuthority()))
                .build();
    }
}
