package com.example.jwt.config.spring;

import com.example.jwt.config.exception.CustomException;
import com.example.jwt.config.exception.ErrorCode;
import com.example.jwt.entity.Account;
import com.example.jwt.repository.AccountRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

import java.util.Collections;

/**
 * @author Lee Taesung
 * @since 2023/02/23
 */
@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {
    private final AccountRepository accountRepository;

    @Override
    public UserDetails loadUserByUsername(String username) {
        return accountRepository.findByEmail(username)
                .map(this::createUserDetails)
                .orElseThrow(() -> new CustomException(ErrorCode.ACCOUNT_NOT_FOUND));
    }

    // DB에 account 값이 존재한다면 UserDetails 객체로 만들어서 반환
    private UserDetails createUserDetails(Account account) {
        SimpleGrantedAuthority grantedAuthority = new SimpleGrantedAuthority(account.getAuthority().toString());

        return new User(account.getEmail(), account.getPassword(), Collections.singleton(grantedAuthority));
    }
}
