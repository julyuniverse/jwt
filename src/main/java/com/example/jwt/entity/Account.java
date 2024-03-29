package com.example.jwt.entity;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.DynamicInsert;
import org.hibernate.annotations.DynamicUpdate;

/**
 * @author Lee Taesung
 * @since 2023/02/23
 */
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Entity
@Table(name = "account")
@DynamicInsert // insert 시 null인 필드 제외
@DynamicUpdate // update 시 null인 필드 제외
public class Account {
    @Id
    @Column(name = "account_id")
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long accountId;
    private String email;
    private String password;
    @Enumerated(EnumType.STRING)
    private Authority authority;

    @Builder
    public Account(String email, String password, Authority authority) {
        this.email = email;
        this.password = password;
        this.authority = authority;
    }
}
