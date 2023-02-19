package com.spring.security.config;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Component
public class JwtUtils {
	private String SECRET_KEY = "secret";

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }
    private Claims extractAllClaims(String token) {
    	JwtParser parser = Jwts.parser();
    	parser.setSigningKey(SECRET_KEY);
    	Jws<Claims> parseClaimsJws = parser.parseClaimsJws(token);
    	Claims claims = parseClaimsJws.getBody();
        return claims;
//        return Jwts.parser().setSigningKey(SECRET_KEY).parseClaimsJws(token).getBody();
    }

    private Boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    public String generateToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        return createToken(claims, userDetails.getUsername());
    }

    private String createToken(Map<String, Object> claims, String subject) {
    	JwtBuilder builder = Jwts.builder();
    	builder.setClaims(claims);
    	builder.setSubject(subject);
    	builder.setIssuedAt(new Date(System.currentTimeMillis()));
    	builder.setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 10));
    	builder.signWith(SignatureAlgorithm.HS256, SECRET_KEY);
    	String jwtString = builder.compact();
    	return jwtString;
//        return Jwts.builder().setClaims(claims).setSubject(subject).setIssuedAt(new Date(System.currentTimeMillis()))
//                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 10))
//                .signWith(SignatureAlgorithm.HS256, SECRET_KEY).compact();
    }

    public Boolean validateToken(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }
    
    public Boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        
        
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }
}
