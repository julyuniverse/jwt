package com.example.jwt.dto.token;

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
@Builder
public class TokenDto {
    private String grantType;
    private String accessToken;
    private Long accessTokenExpiresIn;
    private String refreshToken;
    private Long refreshTokenExpireTime;
}
