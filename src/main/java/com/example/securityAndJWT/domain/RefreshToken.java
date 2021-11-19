package com.example.securityAndJWT.domain;

import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import javax.persistence.Entity;
import javax.persistence.Id;

/**
 * 보통 Token은 만료될 때 자동으로 삭제 처리하기 위해 Redis를 많이 사용한다.
 * 이건 임시로 RDB에 저장하기 위해 테이블을 생성해줌
 * RDB를 저장소로 사용한다면 배치 작업을 통해 만료된 토큰들을 삭제해주는 작업이 필요하다.
 */
@NoArgsConstructor
@Getter
@Entity
public class RefreshToken {
    @Id
    private String key; // member ID 값이 들어간다

    private String value; // RefreshToken String이 들어간다

    public RefreshToken updateValue(String token) {
        this.value = token;
        return this;
    }

    @Builder
    public RefreshToken(String key, String value) {
        this.key = key;
        this.value = value;
    }
}
