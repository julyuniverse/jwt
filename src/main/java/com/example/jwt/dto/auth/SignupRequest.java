package com.example.jwt.dto.auth;

import lombok.*;

/**
 * @author Lee Taesung
 * @since 2023/02/23
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@ToString
public class SignupRequest {
    private String email;
    private String password;
}
