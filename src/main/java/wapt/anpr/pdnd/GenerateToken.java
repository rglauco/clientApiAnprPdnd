package wapt.anpr.pdnd;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Properties;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

/**
 * Utility class to generate JWT tokens for PDND authentication.
 */
public final class GenerateToken {

    private static final Properties properties = new Properties();
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static PrivateKey privateKey;

    static {
        try (InputStream f = new FileInputStream("pdnd.properties")) {
            properties.load(f);
        } catch (IOException e) {
            System.err.println("Error loading pdnd.properties: " + e.getMessage());
        }
        try {
            privateKey = TokenUtils.readPrivateKey(ClientAnpr.fold + "/pk.priv");
        } catch (Exception e) {
            System.err.println("Error loading private key: " + e.getMessage());
        }
    }

    private GenerateToken() {
        // utility class: no instances allowed
    }

    /**
     * Generates a JWT token for requesting an access token from PDND.
     *
     * @param encodedTrack base64-encoded tracking evidence hash
     * @param clientId     PDND client ID
     * @param purposeId    purpose ID
     * @param idToken      unique JWT ID
     * @param kid          key ID (kid header)
     * @param aud          audience claim
     * @return signed JWT string
     * @throws Exception on failure
     */
    public static String getTokenReqAccess(String encodedTrack, String clientId, String purposeId,
                                            String idToken, String kid, String aud) throws Exception {
        long currentTimeInSecs = TokenUtils.currentTimeInSecs();
        long scadenza = currentTimeInSecs + 300; // 5 minutes

        HashMap<String, Object> claims = new HashMap<>();
        claims.put("jti", idToken);
        claims.put("purposeId", purposeId);

        HashMap<String, String> digest = new HashMap<>();
        digest.put("alg", "SHA256");
        digest.put("value", encodedTrack);
        claims.put("digest", digest);

        return Jwts.builder()
                .setClaims(claims)
                .setAudience(aud)
                .setIssuer(clientId)
                .setSubject(clientId)
                .setIssuedAt(Date.from(Instant.ofEpochSecond(currentTimeInSecs)))
                .setExpiration(Date.from(Instant.ofEpochSecond(scadenza)))
                .setHeaderParam("kid", kid)
                .signWith(SignatureAlgorithm.RS256, privateKey)
                .compact();
    }

    /**
     * Generates an Agid-JWT-Signature token.
     *
     * @param digest           base64-encoded body hash
     * @param clientId         PDND client ID
     * @param idToken          unique JWT ID
     * @param aud              audience claim
     * @return signed JWT string
     * @throws Exception on failure
     */
    public static String getAgidJwtSignature(String digest, String clientId, String idToken, String aud) throws Exception {
        long currentTimeInSecs = TokenUtils.currentTimeInSecs();
        long scadenza = currentTimeInSecs + 600; // 10 minutes

        HashMap<String, Object> claims = new HashMap<>();
        claims.put("jti", idToken);

        HashMap<String, String> digestClaim = new HashMap<>();
        digestClaim.put("digest", "SHA-256=" + digest);
        HashMap<String, String> contentTypeClaim = new HashMap<>();
        contentTypeClaim.put("content-type", "application/json");
        claims.put("signed_headers", new Object[]{digestClaim, contentTypeClaim});

        String kid = properties.getProperty("kidPdnd");

        return Jwts.builder()
                .setClaims(claims)
                .setAudience(aud)
                .setIssuer(clientId)
                .setSubject(clientId)
                .setIssuedAt(Date.from(Instant.ofEpochSecond(currentTimeInSecs)))
                .setExpiration(Date.from(Instant.ofEpochSecond(scadenza)))
                .setHeaderParam("typ", "JWT")
                .setHeaderParam("kid", kid)
                .signWith(SignatureAlgorithm.RS256, privateKey)
                .compact();
    }

    /**
     * Generates an Agid-JWT-TrackingEvidence token.
     *
     * @param purposeId        purpose ID
     * @param clientId         PDND client ID
     * @param idToken          unique JWT ID
     * @param aud              audience claim
     * @return signed JWT string
     * @throws Exception on failure
     */
    public static String getAgidTrackingSignature(String purposeId, String clientId, String idToken, String aud) throws Exception {
        long currentTimeInSecs = TokenUtils.currentTimeInSecs();
        long scadenza = currentTimeInSecs + 600; // 10 minutes

        HashMap<String, Object> claims = new HashMap<>();
        claims.put("jti", idToken);
        claims.put("purposeId", purposeId);
        // dnonce: cryptographically random per-call value for replay protection
        claims.put("dnonce", String.valueOf(Math.abs(SECURE_RANDOM.nextLong()) % 10_000_000_000_000L));
        claims.put("userID", properties.getProperty("userID", ""));
        claims.put("userLocation", properties.getProperty("userLocation", ""));
        claims.put("LoA", "LOA3");

        String kid = properties.getProperty("kidPdnd");

        return Jwts.builder()
                .setClaims(claims)
                .setAudience(aud)
                .setIssuer(clientId)
                .setSubject(clientId)
                .setIssuedAt(Date.from(Instant.ofEpochSecond(currentTimeInSecs)))
                .setExpiration(Date.from(Instant.ofEpochSecond(scadenza)))
                .setHeaderParam("typ", "JWT")
                .setHeaderParam("kid", kid)
                .signWith(SignatureAlgorithm.RS256, privateKey)
                .compact();
    }
}
