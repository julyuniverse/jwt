package com.example.jwt.dto.account;

import lombok.*;

/**
 * @author Lee Taesung
 * @since 2023/02/24
 */
@Getter
@Setter
@NoArgsConstructor
@ToString
public class Account {
    private Long accountId;
    private String email;
    private String role;

    @Builder
    public Account(Long accountId, String email, String role) {
        this.accountId = accountId;
        this.email = email;
        this.role = role;
    }
}
