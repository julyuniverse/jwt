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
public class Token {
    private String accessToken;
    private String refreshToken;
}
