package com.example.securityAndJWT.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import javax.persistence.*;

@NoArgsConstructor
@Getter
@Entity
public class Member {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String email; // 로그인 ID로 쓰임

    private String password;

    private String name;

    @Enumerated(EnumType.STRING)
    private Authority authority;

    @Builder
    public Member(String email, String password, String name, Authority authority) {
        this.email = email;
        this.password = password;
        this.name = name;
        this.authority = authority;
    }
}
