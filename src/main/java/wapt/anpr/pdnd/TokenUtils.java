package wapt.anpr.pdnd;


import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;



public class TokenUtils {

    public TokenUtils() {
        // no-op: utility class
    }

    //91366318
    public static PrivateKey getPrivateKeyFromKeystore(String pwd, String alias) throws Exception{
    	String pathFileKeystore=ClientAnpr.fold+"/"+"token.p12";
    	String typeKeystore="PKCS12";
    	String aliascertificato=alias;
    	String keystorePassword=pwd;
    	
    	KeyStore ks = KeyStore.getInstance(typeKeystore);
    	InputStream readStream = new FileInputStream(pathFileKeystore); 
    	ks.load(readStream, keystorePassword.toCharArray());
    	PrivateKey pk = (PrivateKey)ks.getKey(aliascertificato, keystorePassword.toCharArray());
    	readStream.close();
    	
    	return pk;
    } 
   
    /**
     * Read a PEM encoded private key from the classpath
     *
     * @param pemResName - key file resource name
     * @return PrivateKey
     * @throws Exception on decode failure
     */
    public static PrivateKey readPrivateKey(final String pemResName) throws Exception {
        try (InputStream contentIS = new FileInputStream(pemResName)) {
            byte[] tmp = new byte[4096];
            int length = contentIS.read(tmp);
            return decodePrivateKey(new String(tmp, 0, length, "UTF-8"));
        }
    }
    
    public static PrivateKey getPrivateKeyPkcs8(String filename) throws Exception {

    	byte[] keyBytes = Files.readAllBytes(Paths.get(filename));

    	PKCS8EncodedKeySpec spec =
    			new PKCS8EncodedKeySpec(keyBytes);
    	KeyFactory kf = KeyFactory.getInstance("RSA");
    	return kf.generatePrivate(spec);
    }

    /**
     * Generate a new RSA keypair.
     *
     * @param keySize - the size of the key
     * @return KeyPair
     * @throws NoSuchAlgorithmException on failure to load RSA key generator
     */
    public static KeyPair generateKeyPair(final int keySize) throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(keySize);
        return keyPairGenerator.genKeyPair();
    }

    /**
     * Decode a PEM encoded private key string to an RSA PrivateKey
     *
     * @param pemEncoded - PEM string for private key
     * @return PrivateKey
     * @throws Exception on decode failure
     */
    public static PrivateKey decodePrivateKey(final String pemEncoded) throws Exception {
        byte[] encodedBytes = toEncodedBytes(pemEncoded);

        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encodedBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(keySpec);
    }

    /**
     * Decode a PEM encoded public key string to an RSA PublicKey
     *
     * @param pemEncoded - PEM string for private key
     * @return PublicKey
     * @throws Exception on decode failure
     */
    public static PublicKey decodePublicKey(String pemEncoded) throws Exception {
        byte[] encodedBytes = toEncodedBytes(pemEncoded);

        X509EncodedKeySpec spec = new X509EncodedKeySpec(encodedBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }

    private static byte[] toEncodedBytes(final String pemEncoded) {
        final String normalizedPem = removeBeginEnd(pemEncoded);
        return Base64.getDecoder().decode(normalizedPem);
    }

    private static String removeBeginEnd(String pem) {
        pem = pem.replaceAll("-----BEGIN (.*)-----", "");
        pem = pem.replaceAll("-----END (.*)----", "");
        pem = pem.replaceAll("\r\n", "");
        pem = pem.replaceAll("\n", "");
        return pem.trim();
    }

    /**
     * @return the current time in seconds since epoch
     */
    public static int currentTimeInSecs() {
        long currentTimeMS = System.currentTimeMillis();
        return (int) (currentTimeMS / 1000);
    }

}
