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
import java.util.Properties;
import java.util.UUID;

import javax.ws.rs.core.Response.Status;

import org.apache.commons.io.IOUtils;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

public class AccessTokenPdnd {
	
	private static Properties properties = new Properties();
	
	static{
		try {
			InputStream f = new FileInputStream("pdnd.properties");
			properties.load(f);
		} catch (IOException e){
			e.printStackTrace();
		}
	}

	public String getRequestAccessToken(String encodedTrack, String PurposeId) throws Exception {

		String token = null;
		
		try {
			
			String aud = (String)properties.get("audPdnd");
			String kid = (String)properties.get("kidPdnd");
			String purposeId = PurposeId;
			String clientId = (String)properties.get("clientIdPdnd");
			
			String baseUrl = (String)properties.get("urltokenPdnd");
			URL url = new URL(baseUrl+"/token.oauth2");
			
			URLConnection connection = null;
			if(!"".equals(properties.get("proxypwd"))) {
				Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress((String)properties.get("proxyhost"), Integer.parseInt((String)properties.get("proxyport"))));
				Authenticator authenticator = new Authenticator() {
			        public PasswordAuthentication getPasswordAuthentication() {
			            return (new PasswordAuthentication((String)properties.get("proxyuser"),
			            		((String)properties.get("proxypwd")).toCharArray()));
			        }
			    };
			    Authenticator.setDefault(authenticator);
				connection = url.openConnection(proxy);
			}else {
				connection = url.openConnection();
			}
			
						
			HttpURLConnection myURLConnection = (HttpURLConnection) connection;
	
			myURLConnection.setRequestMethod("POST");
			myURLConnection.setRequestProperty("Accept", "application/json");
			myURLConnection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
			myURLConnection.setUseCaches(false);
			myURLConnection.setDoInput(true);
			myURLConnection.setDoOutput(true);
			
			String idToken = UUID.randomUUID().toString();
			String jwtToken = GenerateToken.getTokenReqAccess(encodedTrack, clientId, purposeId, idToken, kid, aud);
			//System.out.println(jwtToken);
			String jsonInputString = "client_id="+clientId;
			jsonInputString += "&client_assertion="+jwtToken;
			jsonInputString += "&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer";
			jsonInputString += "&grant_type=client_credentials";
						
			try(OutputStream os = myURLConnection.getOutputStream()) {
			    byte[] input = jsonInputString.getBytes("utf-8");
			    os.write(input, 0, input.length);			
			}
			
			
			int responseCode = myURLConnection.getResponseCode();
	
	        if (responseCode == Status.OK.getStatusCode()) {
	            InputStream inputStr = myURLConnection.getInputStream();
	            String encoding = connection.getContentEncoding() == null ? "UTF-8" : connection.getContentEncoding();
	            String jsonResponse = IOUtils.toString(inputStr, encoding);
	            
	            JsonObject jsonObject = new JsonParser().parse(jsonResponse).getAsJsonObject();
	            token = jsonObject.get("access_token").getAsString();
	            
	        }else {
	        	InputStream inputStr = myURLConnection.getErrorStream();
	        	String encoding = connection.getContentEncoding() == null ? "UTF-8" : connection.getContentEncoding();
	            String jsonResponse = IOUtils.toString(inputStr, encoding);
	        	throw new Exception(jsonResponse);
	        }
            
	        myURLConnection.disconnect();
		
		}catch (Exception e) {
			e.printStackTrace();
			throw e;
		}		

		return token;
	}
	
}
