package sn.edu.uadb.test_spring_security.security;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;

@Component
public class JwtUtils {
    private static final Logger logger= LoggerFactory.getLogger(JwtUtils.class);
    @Value("${spring.app.jwtSecret}")
    private String jwtSecret;
    @Value("${spring.app.jwtExpiration}")
    private int jwtExpiration;
    //Cette fonction permet de recuperer le token dans la requete
    public String getTokenFromHeader(HttpServletRequest request){
        String bearerToken = request.getHeader("Authorization");
        if(bearerToken != null && bearerToken.startsWith("Bearer")){
            return bearerToken.substring(7);
        }
        return  null;
    }
    //Cette methode genere un token
    public String generateTokenFromUsername(UserDetails userDetails){
        String username= userDetails.getUsername();
        Date creationDate= new Date();
        long expirartion = creationDate.getTime() + jwtExpiration;
        return  Jwts.builder()
                .subject(username)
                .issuedAt(creationDate)
                .expiration(new Date(expirartion))
                .signWith(getKey())
                .compact();
    }

    private SecretKey getKey() {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
    }

    public String getUsernameFromToken(String token){
        return  Jwts.parser()
                .verifyWith( (SecretKey) getKey())
                .build().
                parseSignedClaims(token)
                .getPayload()
                .getSubject();
    }

    public  boolean validateToken(String authToken){
        try {
            Jwts.parser().verifyWith((SecretKey) getKey()).build().parseSignedClaims(authToken);
            return true;
        }catch (MalformedJwtException m){
            throw new RuntimeException("JWT invalid "+m.getMessage());
        }catch (ExpiredJwtException e){
            throw new RuntimeException("Le JWT a expire "+e.getMessage());
        }catch (UnsupportedJwtException u){
            throw new RuntimeException("Le JWT n'est pas supporte "+u.getMessage());
        }catch (IllegalArgumentException i){
            throw new RuntimeException("Le contenu du JWT est vide "+i.getMessage());
        }
    }

}
