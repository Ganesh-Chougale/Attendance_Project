package com.AttendaceBE.Security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.SignatureException;
import io.jsonwebtoken.ExpiredJwtException; // Add this import
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
        final Claims claims = extractAllClaims(token); // SignatureException typically occurs here
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
            // These lines are for *secondary* validation after the token has been successfully parsed.
            // If extractUsername or extractExpiration (which call extractAllClaims) threw an exception,
            // the execution would already be in the catch block of JwtAuthenticationFilter.
            final String username = extractUsername(token); // This call might implicitly succeed if no SignatureException occurred earlier.

            final Date expiration = extractExpiration(token);
            final Date now = new Date();

            System.out.println("DEBUG (JwtService.isTokenValid): Token Extracted Username: " + username);
            System.out.println("DEBUG (JwtService.isTokenValid): UserDetails Username: " + userDetails.getUsername());
            System.out.println("DEBUG (JwtService.isTokenValid): Token Expiration: " + expiration);
            System.out.println("DEBUG (JwtService.isTokenValid): Current Time: " + now);
            System.out.println("DEBUG (JwtService.isTokenValid): Is token expired? " + expiration.before(now));
            System.out.println("DEBUG (JwtService.isTokenValid): Is username match? " + (username.equals(userDetails.getUsername())));

            return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
        } catch (SignatureException e) {
            // This catch block might not be hit if JwtAuthenticationFilter's earlier catch handles it.
            System.err.println("ERROR (JwtService.isTokenValid): Invalid JWT signature! (This should be caught earlier if filter is working)");
            System.err.println("Exception details: " + e.getMessage());
            e.printStackTrace();
            return false;
        } catch (ExpiredJwtException e) { // Catch ExpiredJwtException specifically here too
            System.err.println("ERROR (JwtService.isTokenValid): JWT has expired! (This should be caught earlier if filter is working)");
            System.err.println("Exception details: " + e.getMessage());
            e.printStackTrace();
            return false;
        } catch (Exception e) {
            System.err.println("ERROR (JwtService.isTokenValid): Generic error validating token: " + e.getMessage());
            e.printStackTrace();
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
        // This is the core parsing and verification step.
        // If the signature is invalid, SignatureException will be thrown here.
        // If the token is expired during parsing, ExpiredJwtException will be thrown here.
        return Jwts
                .parser()
                .verifyWith(getSignInKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    private SecretKey getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}