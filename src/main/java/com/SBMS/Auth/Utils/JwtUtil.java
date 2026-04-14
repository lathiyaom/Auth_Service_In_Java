package com.SBMS.Auth.Utils;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.*;
import jakarta.annotation.PostConstruct;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.UUID;

public class JwtUtil {

    private String jwtSecret;

    private long accessTokenExpiration;

    private long refreshTokenExpiration;

    private SecretKey key;

    @PostConstruct
    public void init() {
        this.key = Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
    }

    public String generateRefreshToken(String username) {
        return buildToken(username, refreshTokenExpiration);
    }

    private String buildToken(String username, long expiration) {

        return Jwts.builder()
                .setSubject(username)
                .setId(UUID.randomUUID().toString())
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(key)
                .compact();
    }

    public Claims extractClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key).build()
                .parseClaimsJwt(token).getBody();
    }

    public String extractUsername(String token) {
        return extractClaims(token).getSubject();
    }

    public String extractTokenId(String token) {
        return extractClaims(token).getId();
    }

    public boolean isValid(String token, String username) {
        final Claims claims = extractClaims(token);
        return claims.getSubject().equals(username) && !IsExpired(claims);
    }

    public boolean IsExpired(Claims claims) {
        return claims.getExpiration().before(new Date());
    }
}
