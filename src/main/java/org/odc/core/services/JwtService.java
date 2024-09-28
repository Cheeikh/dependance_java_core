package org.odc.core.services;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    // Clé secrète sécurisée générée pour HS256
    private final Key SECRET_KEY = Keys.secretKeyFor(SignatureAlgorithm.HS256); // Assurez-vous d'utiliser la même clé pour signer et vérifier

    // Extraire le nom d'utilisateur du token
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    // Extraire des claims spécifiques du token
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    // Extraire tous les claims du token
    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(SECRET_KEY) // Assurez-vous que la même clé est utilisée ici
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    // Générer un token JWT avec des claims supplémentaires, expiration et signature HS256
    public String generateToken(String username, List<String> roles) {
        Map<String, Object> extraClaims = new HashMap<>();
        extraClaims.put("roles", roles);  // Ajouter les rôles dynamiquement

        return Jwts.builder()
                .setClaims(extraClaims)  // Ajouter des claims personnalisés (y compris les rôles)
                .setSubject(username)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 10))  // 10 heures d'expiration
                .signWith(SECRET_KEY, SignatureAlgorithm.HS256)  // Signer avec la clé secrète
                .compact();
    }

    // Valider le token pour un utilisateur donné
    public boolean isTokenValid(String token, String username) {
        return (extractUsername(token).equals(username)) && !isTokenExpired(token);
    }

    // Vérifier si le token a expiré
    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    // Extraire la date d'expiration du token
    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }
}
