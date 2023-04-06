package com.example.jwt.dto.account;

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
public class Account {
    private Long accountId;
    private String email;
    private String role;
}
