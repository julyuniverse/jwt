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
@AllArgsConstructor
@Builder
public class LoginResponse {
    private Account account;
    private Token token;
}
