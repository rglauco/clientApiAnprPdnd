package wapt.anpr.pdnd;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Authenticator;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.PasswordAuthentication;
import java.net.Proxy;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Properties;
import java.util.UUID;

import javax.ws.rs.core.Response.Status;

import org.apache.commons.io.IOUtils;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

public class AccessTokenPdnd {
	
	private static final Properties properties = new Properties();
	
	static {
		try (InputStream f = new FileInputStream("pdnd.properties")) {
			properties.load(f);
		} catch (IOException e) {
			System.err.println("Error loading pdnd.properties: " + e.getMessage());
		}
	}

	public String getRequestAccessToken(String encodedTrack, String purposeId) throws Exception {
		String token = null;

		try {
			String aud = properties.getProperty("audPdnd");
			String kid = properties.getProperty("kidPdnd");
			String clientId = properties.getProperty("clientIdPdnd");
			String baseUrl = properties.getProperty("urltokenPdnd");

			if (aud == null || kid == null || clientId == null || baseUrl == null) {
				throw new IllegalStateException("Missing required configuration in pdnd.properties");
			}

			URL url = new URL(baseUrl + "/token.oauth2");
			URLConnection connection = null;

			String proxyHost = properties.getProperty("proxyhost");
			String proxypwd = properties.getProperty("proxypwd");

			if (proxyHost != null && !proxyHost.isEmpty()) {
				int proxyPort = Integer.parseInt(properties.getProperty("proxyport", "8080"));
				Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(proxyHost, proxyPort));
				if (proxypwd != null && !proxypwd.isEmpty()) {
					Authenticator authenticator = new Authenticator() {
						@Override
						public PasswordAuthentication getPasswordAuthentication() {
							return new PasswordAuthentication(properties.getProperty("proxyuser", ""),
									proxypwd.toCharArray());
						}
					};
					Authenticator.setDefault(authenticator);
				}
				connection = url.openConnection(proxy);
			} else {
				connection = url.openConnection();
			}

			HttpURLConnection myURLConnection = (HttpURLConnection) connection;

			myURLConnection.setRequestMethod("POST");
			myURLConnection.setRequestProperty("Accept", "application/json");
			myURLConnection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
			myURLConnection.setUseCaches(false);
			myURLConnection.setDoInput(true);
			myURLConnection.setDoOutput(true);
			myURLConnection.setConnectTimeout(10000);
			myURLConnection.setReadTimeout(10000);

			String idToken = UUID.randomUUID().toString();
			String jwtToken = GenerateToken.getTokenReqAccess(encodedTrack, clientId, purposeId, idToken, kid, aud);

			StringBuilder sb = new StringBuilder();
			sb.append("client_id=").append(URLEncoder.encode(clientId, StandardCharsets.UTF_8.name()));
			sb.append("&client_assertion=").append(URLEncoder.encode(jwtToken, StandardCharsets.UTF_8.name()));
			sb.append("&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer");
			sb.append("&grant_type=client_credentials");

			try (OutputStream os = myURLConnection.getOutputStream()) {
				os.write(sb.toString().getBytes(StandardCharsets.UTF_8));
			}

			int responseCode = myURLConnection.getResponseCode();

			try {
				if (responseCode == Status.OK.getStatusCode()) {
					try (InputStream inputStr = myURLConnection.getInputStream()) {
						String encoding = connection.getContentEncoding() == null ? "UTF-8" : connection.getContentEncoding();
						String jsonResponse = IOUtils.toString(inputStr, encoding);

						JsonObject jsonObject = new JsonParser().parse(jsonResponse).getAsJsonObject();
						token = jsonObject.get("access_token").getAsString();
					}
				} else {
					try (InputStream inputStr = myURLConnection.getErrorStream()) {
						String encoding = connection.getContentEncoding() == null ? "UTF-8" : connection.getContentEncoding();
						String jsonResponse = (inputStr != null) ? IOUtils.toString(inputStr, encoding) : "No error stream";
						throw new Exception("HTTP Error " + responseCode + ": " + jsonResponse);
					}
				}
			} finally {
				myURLConnection.disconnect();
			}

		} catch (Exception e) {
			System.err.println("Error requesting access token: " + e.getMessage());
			throw e;
		}

		return token;
	}
}
