package com.example.jwt.dto.auth;

import com.example.jwt.dto.account.Account;
import com.example.jwt.dto.token.Token;
import lombok.*;

/**
 * @author Lee Taesung
 * @since 2023/02/24
 */
@Getter
@Setter
@NoArgsConstructor
@ToString
public class LoginResponse {
    private Account account;
    private Token token;

    @Builder
    public LoginResponse(Account account, Token token) {
        this.account = account;
        this.token = token;
    }
}
