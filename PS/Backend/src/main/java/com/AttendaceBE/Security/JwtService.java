package com.AttendaceBE.Security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.SignatureException; // Ensure this import is present
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    @Value("${application.security.jwt.secret-key}")
    private String secretKey;

    @Value("${application.security.jwt.expiration}")
    private long jwtExpiration;

    @Value("${application.security.jwt.refresh-token.expiration}")
    private long refreshExpiration;

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token); // This is where the SignatureException likely happens
        return claimsResolver.apply(claims);
    }

    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    public String generateToken(
            Map<String, Object> extraClaims,
            UserDetails userDetails
    ) {
        return buildToken(extraClaims, userDetails, jwtExpiration);
    }

    public String generateRefreshToken(
            UserDetails userDetails
    ) {
        return buildToken(new HashMap<>(), userDetails, refreshExpiration);
    }

    private String buildToken(
            Map<String, Object> extraClaims,
            UserDetails userDetails,
            long expiration
    ) {
        return Jwts
                .builder()
                .claims(extraClaims)
                .subject(userDetails.getUsername())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(getSignInKey())
                .compact();
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        try {
            // These lines were executed before because extractUsername calls extractAllClaims internally
            // The issue is likely within extractAllClaims
            final String username = extractUsername(token); // This calls extractAllClaims
            
            // Now, explicitly check other conditions *after* successful claim extraction
            final Date expiration = extractExpiration(token); // This also calls extractAllClaims
            final Date now = new Date();

            System.out.println("DEBUG: Token Extracted Username: " + username);
            System.out.println("DEBUG: UserDetails Username: " + userDetails.getUsername());
            System.out.println("DEBUG: Token Expiration: " + expiration);
            System.out.println("DEBUG: Current Time: " + now);
            System.out.println("DEBUG: Is token expired? " + expiration.before(now));
            System.out.println("DEBUG: Is username match? " + (username.equals(userDetails.getUsername())));

            return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
        } catch (SignatureException e) {
            System.err.println("ERROR: Invalid JWT signature! This token was signed with a different key or is corrupted.");
            System.err.println("Exception details: " + e.getMessage());
            e.printStackTrace(); // Print full stack trace for more details
            return false;
        } catch (Exception e) {
            System.err.println("ERROR: Generic error validating token: " + e.getMessage());
            e.printStackTrace(); // Print full stack trace for other exceptions
            return false;
        }
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    private Claims extractAllClaims(String token) {
        return Jwts
                .parser()
                .verifyWith(getSignInKey()) // This is the crucial line for signature verification
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    private SecretKey getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}