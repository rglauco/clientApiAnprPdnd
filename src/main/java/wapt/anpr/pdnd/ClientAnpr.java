package wapt.anpr.pdnd;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDate;
import java.util.Base64;
import java.util.Properties;
import java.util.UUID;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.ws.rs.core.Response.Status;

import org.apache.commons.io.IOUtils;
import org.json.JSONObject;

public class ClientAnpr {

    private static final Properties properties = new Properties();

    static {
        try (InputStream f = new FileInputStream("pdnd.properties")) {
            properties.load(f);
        } catch (IOException e) {
            System.err.println("Error loading pdnd.properties: " + e.getMessage());
        }
    }

    /**
     * Directory where keystore and private key files are stored.
     * This is intentionally package-visible for use by other classes in this package.
     */
    public static String fold = "store";

    public static void main(String[] args) {
        // WARNING: Disables all SSL certificate validation.
        // This should only be used in controlled/test environments.
        setupTrustManager();

        try {
            String tokenTrackSignC030 = generateTokenAudit(
                    properties.getProperty("purposeIdPdnd_c030"),
                    properties.getProperty("clientIdPdnd"),
                    properties.getProperty("audTokenAgidJwtSignature_c030"));
            String encodedTrackC030 = generateHashHex(tokenTrackSignC030);

            AccessTokenPdnd pC030 = new AccessTokenPdnd();
            String tokenC030 = pC030.getRequestAccessToken(
                    encodedTrackC030,
                    properties.getProperty("purposeIdPdnd_c030"));

            String jsonInputStringC030 = readFileContent(
                    ClientAnpr.fold + "/" + properties.getProperty("fileTest_c030"));
            String encodedBodyC030 = generateHashBase64(jsonInputStringC030);
            String tokenAgidSignC030 = generateJwtSignature(
                    encodedBodyC030,
                    properties.getProperty("clientIdPdnd"),
                    properties.getProperty("audTokenAgidJwtSignature_c030"));

            String baseUrlC030 = properties.getProperty("baseurlapi_c030");
            String jsonResponseC030 = sendHttpRequest(
                    baseUrlC030, tokenC030, tokenAgidSignC030,
                    tokenTrackSignC030, encodedBodyC030, jsonInputStringC030);
            JSONObject jsonObject = new JSONObject(jsonResponseC030);

            String idANPR = jsonObject
                    .getJSONObject("listaSoggetti")
                    .getJSONArray("datiSoggetto")
                    .getJSONObject(0)
                    .getJSONObject("identificativi")
                    .getString("idANPR");

            String tokenTrackSignC001 = generateTokenAudit(
                    properties.getProperty("purposeIdPdnd_c001"),
                    properties.getProperty("clientIdPdnd"),
                    properties.getProperty("audTokenAgidJwtSignature_c001"));
            String encodedTrackC001 = generateHashHex(tokenTrackSignC001);

            AccessTokenPdnd pC001 = new AccessTokenPdnd();
            String tokenC001 = pC001.getRequestAccessToken(
                    encodedTrackC001,
                    properties.getProperty("purposeIdPdnd_c001"));

            String jsonInputStringC001 = generateJsonInputStringC001(idANPR);
            String encodedBodyC001 = generateHashBase64(jsonInputStringC001);
            String tokenAgidSignC001 = generateJwtSignature(
                    encodedBodyC001,
                    properties.getProperty("clientIdPdnd"),
                    properties.getProperty("audTokenAgidJwtSignature_c001"));

            String baseUrlC001 = properties.getProperty("baseurlapi_c001");
            sendHttpRequest(
                    baseUrlC001, tokenC001, tokenAgidSignC001,
                    tokenTrackSignC001, encodedBodyC001, jsonInputStringC001);

        } catch (Exception e) {
            System.err.println("Error in main execution: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Configures a trust manager that accepts all SSL certificates.
     * <p>
     * <strong>Security Warning:</strong> This disables certificate validation
     * and should only be used in controlled/test environments. In production,
     * use the default JSSE truststore or configure a proper one.
     * </p>
     */
    private static void setupTrustManager() {
        TrustManager[] trustAllCerts = new TrustManager[]{
                new X509TrustManager() {
                    public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                        return new java.security.cert.X509Certificate[0];
                    }

                    public void checkClientTrusted(java.security.cert.X509Certificate[] certs, String authType) {
                        // no-op: accepts all clients
                    }

                    public void checkServerTrusted(java.security.cert.X509Certificate[] certs, String authType) {
                        // no-op: accepts all servers
                    }
                }
        };

        try {
            SSLContext sc = SSLContext.getInstance("SSL");
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
        } catch (Exception e) {
            System.err.println("Error setting up trust manager: " + e.getMessage());
        }
    }

    private static String generateTokenAudit(String purposeId, String clientId, String audTokenSignature)
            throws Exception {
        String idTokenTrack = UUID.randomUUID().toString();
        return GenerateToken.getAgidTrackingSignature(purposeId, clientId, idTokenTrack, audTokenSignature);
    }

    private static String generateHashHex(String input) throws NoSuchAlgorithmException {
        MessageDigest digestTrack = MessageDigest.getInstance("SHA-256");
        byte[] hashTrack = digestTrack.digest(input.getBytes(StandardCharsets.UTF_8));
        StringBuilder hexString = new StringBuilder();
        for (byte b : hashTrack) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }

    private static String generateHashBase64(String input) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(hash);
    }

    private static String generateJwtSignature(String encodedBody, String clientId, String audTokenSignature)
            throws Exception {
        String idToken = UUID.randomUUID().toString();
        return GenerateToken.getAgidJwtSignature(encodedBody, clientId, idToken, audTokenSignature);
    }

    private static String readFileContent(String filepath) throws IOException {
        try (FileInputStream fileInputStream = new FileInputStream(filepath)) {
            return IOUtils.toString(fileInputStream, StandardCharsets.UTF_8);
        }
    }

    /**
     * Sends an HTTP POST request to the ANPR API endpoint.
     *
     * @param baseUrl             the API endpoint URL
     * @param token               the bearer access token
     * @param tokenAgidSign       the Agid-JWT-Signature header value
     * @param tokenTrackSign      the Agid-JWT-TrackingEvidence header value
     * @param encodedBody         the base64-encoded SHA-256 digest of the body
     * @param jsonInputString     the JSON body to send
     * @return the HTTP response body as a string
     * @throws IOException on network or protocol error
     */
    private static String sendHttpRequest(String baseUrl, String token, String tokenAgidSign,
                                           String tokenTrackSign, String encodedBody,
                                           String jsonInputString) throws IOException {
        URL url = new URL(baseUrl);
        URLConnection connection = url.openConnection();
        HttpURLConnection myURLConnection = (HttpURLConnection) connection;

        myURLConnection.setRequestMethod("POST");
        myURLConnection.setUseCaches(false);
        myURLConnection.setDoInput(true);
        myURLConnection.setDoOutput(true);
        myURLConnection.setConnectTimeout(10000);
        myURLConnection.setReadTimeout(10000);

        myURLConnection.setRequestProperty("Authorization", "Bearer " + token);
        myURLConnection.setRequestProperty("Agid-JWT-Signature", tokenAgidSign);
        myURLConnection.setRequestProperty("Agid-JWT-TrackingEvidence", tokenTrackSign);
        myURLConnection.setRequestProperty("Digest", "SHA-256=" + encodedBody);
        myURLConnection.setRequestProperty("Content-Type", "application/json");

        try (OutputStream os = myURLConnection.getOutputStream()) {
            byte[] input = jsonInputString.getBytes(StandardCharsets.UTF_8);
            os.write(input, 0, input.length);
        }

        int responseCode = myURLConnection.getResponseCode();
        String encoding = connection.getContentEncoding() == null ? "UTF-8" : connection.getContentEncoding();
        String jsonResponse;

        if (responseCode == Status.OK.getStatusCode()) {
            try (InputStream inputStr = myURLConnection.getInputStream()) {
                jsonResponse = IOUtils.toString(inputStr, encoding);
                System.out.println("Response (" + responseCode + "): " + jsonResponse);
            }
        } else {
            System.out.println("GovWay-Transaction-ID: " +
                    myURLConnection.getHeaderField("GovWay-Transaction-ID"));
            try (InputStream inputStr = myURLConnection.getErrorStream()) {
                jsonResponse = (inputStr != null)
                        ? IOUtils.toString(inputStr, encoding)
                        : "No error stream available";
                System.out.println("Error Response (" + responseCode + "): " + jsonResponse);
            }
        }

        myURLConnection.disconnect();
        return jsonResponse;
    }

    private static String generateJsonInputStringC001(String idANPR) {
        return " { \"idOperazioneClient\": \"1\", \"criteriRicerca\": { \"idANPR\": \"" + idANPR
                + "\" }, \"datiRichiesta\": { \"dataRiferimentoRichiesta\": \"" + LocalDate.now()
                + "\", \"motivoRichiesta\": \"1\", \"casoUso\": \"C001\" } }";
    }
}
