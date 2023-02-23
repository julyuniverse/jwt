package com.example.jwt.repository;

import com.example.jwt.entity.RefreshToken;
import org.springframework.data.repository.CrudRepository;

/**
 * @author Lee Taesung
 * @since 2023/02/23
 */
public interface RefreshTokenRepository extends CrudRepository<RefreshToken, String> {
}
