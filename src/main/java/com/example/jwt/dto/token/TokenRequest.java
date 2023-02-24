package com.example.jwt.dto.token;

import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * @author Lee Taesung
 * @since 2023/02/24
 */
@Getter
@NoArgsConstructor
public class TokenRequest {
    private String accessToken;
    private String refreshToken;
}
