package com.example.jwt.contoller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author Lee Taesung
 * @since 2023/02/24
 */
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/account")
public class AccountController {

    @GetMapping("/string")
    public ResponseEntity<String> string() {
        return ResponseEntity.ok("string");
    }
}
