package com.example.demo.domain.auth.service;

import com.example.demo.global.auth.jwt.JwtProvider;
import com.example.demo.global.common.constants.TokenConstants;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.Date;
import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
public class TokenService {

    private final StringRedisTemplate redisTemplate;
    private final JwtProvider jwtProvider;

    // 이메일을 Key로 가지는 Refresh 토큰 저장
    public void saveRefreshToken(String refreshToken, String email) {
        Claims claims = jwtProvider.getClaims(refreshToken);
        long expiration = claims.getExpiration().getTime();

        redisTemplate.opsForValue().set(
                TokenConstants.REFRESH_TOKEN_KEY + email,
                refreshToken,
                expiration,
                TimeUnit.MILLISECONDS
        );
    }

    public void deleteRefreshToken(String email) {
        String key = TokenConstants.REFRESH_TOKEN_KEY + email;
        redisTemplate.delete(key);
    }

    public String getRefreshToken(String email) {
        String key = TokenConstants.REFRESH_TOKEN_KEY + email;

        return redisTemplate.opsForValue().get(key);
    }

    public void validRefreshToken(String email, String refreshToken) {
        String token = getRefreshToken(email);

        if (token == null) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Refresh Token이 존재하지 않습니다.");
        }

        if (!token.equals(refreshToken)) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "유효하지 않은 Refresh Token입니다.");
        }
    }

    // Access 토큰을 블랙리스트에 저장하여 관리
    public void saveAccessToken(String accessToken) {
        long now = new Date().getTime();
        Claims claims = jwtProvider.getClaims(accessToken);
        Date expiration = claims.getExpiration();
        long remainExpiration = expiration.getTime() - now;

        // Access 토큰이 아직 유효하다면 블랙리스트에 저장
        if (remainExpiration > 0) {
            redisTemplate.opsForValue().set(
                    TokenConstants.BLACKLIST_KEY + accessToken,
                    TokenConstants.BLACKLIST_VALUE,
                    remainExpiration,
                    TimeUnit.MILLISECONDS
            );
        }
    }

    // BlackList key가 존재하면 true
    public boolean validBlackList(String accessToken) {
        return redisTemplate.hasKey(TokenConstants.BLACKLIST_KEY + accessToken);
    }
}
