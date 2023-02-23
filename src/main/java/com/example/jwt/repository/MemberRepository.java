package com.example.jwt.repository;

import com.example.jwt.entity.Member;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

/**
 * @author Lee Taesung
 * @since 2023/02/23
 */
public interface MemberRepository extends JpaRepository<Member, Long> {
    Optional<Member> findByEmail(String email);

    boolean existsByEmail(String email); // 중복 체크
}