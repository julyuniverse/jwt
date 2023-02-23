package com.example.jwt.config.exception;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.http.HttpStatus;

import static org.springframework.http.HttpStatus.UNAUTHORIZED;

/**
 * @author Lee Taesung
 * @since 2023/02/23
 */
@AllArgsConstructor
@Getter
public enum ErrorCode {
    DUPLICATE_ID(UNAUTHORIZED, "Duplicate ID."),
    WRONG_PASSWORD(UNAUTHORIZED, "Wrong password."),

    NOT_FOUND_IN_DB(UNAUTHORIZED, "Not found in database."),
    ;

    private final HttpStatus httpStatus;
    private final String message;
}
