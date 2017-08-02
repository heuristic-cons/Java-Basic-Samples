
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.net.URISyntaxException;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.apache.commons.codec.binary.Base64;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.ParseException;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPatch;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.client.utils.URLEncodedUtils;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.protocol.HTTP;
import org.apache.http.util.EntityUtils;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

public class OAuthUtils {

	public static OAuth2Details createOAuthDetails(Properties config) {
		OAuth2Details oauthDetails = new OAuth2Details();
		oauthDetails.setAccessToken((String) config.get(OAuthConstants.ACCESS_TOKEN));
		
		oauthDetails.setRefreshToken((String) config.get(OAuthConstants.REFRESH_TOKEN));
		
		oauthDetails.setGrantType((String) config.get(OAuthConstants.GRANT_TYPE));
		
		oauthDetails.setClientId((String) config.get(OAuthConstants.CLIENT_ID));
		
		oauthDetails.setClientSecret((String) config.get(OAuthConstants.CLIENT_SECRET));
		
		oauthDetails.setScope((String) config.get(OAuthConstants.SCOPE));
		
		oauthDetails.setAuthenticationServerUrl((String) config.get(OAuthConstants.AUTHENTICATION_SERVER_URL));
		
		oauthDetails.setUsername((String) config.get(OAuthConstants.USERNAME));
		
		oauthDetails.setPassword((String) config.get(OAuthConstants.PASSWORD));
		
		oauthDetails.setResourceServerUrl((String) config.get(OAuthConstants.RESOURCE_SERVER_URL));
		
		if(!isValid(oauthDetails.getResourceServerUrl())){
			System.out.println("Resource server url is null. Will assume request is for generating Access token");
			oauthDetails.setAccessTokenRequest(true);
		}

		return oauthDetails;
	}

	public static Properties getClientConfigProps(String path) 
	{
		InputStream is = OAuthUtils.class.getClassLoader().getResourceAsStream(path);
		Properties config = new Properties();
		try {
			config.load(is);
		} 
		catch (IOException e) {
			System.out.println("Could not load properties from " + path);
			e.printStackTrace();
			return null;
		}
		return config;
	}

	public static void getProtectedResource(OAuth2Details oauthDetails) 
	{
		
		String resourceURL = oauthDetails.getResourceServerUrl();
				
		HttpGet get = new HttpGet(resourceURL + packUrl());
                get.addHeader(OAuthConstants.EMVS_DATA_ENTRY_MODE, OAuthConstants.EMVS_DATA_ENTRY_MODE_NONMANUAL);
		get.addHeader(OAuthConstants.AUTHORIZATION,
				getAuthorizationHeaderForAccessToken(oauthDetails
						.getAccessToken()));
		
		DefaultHttpClient client = new DefaultHttpClient();
		HttpResponse response = null;
		int code = -1;
			    
		try 
		{
			response = client.execute(get);
			code = response.getStatusLine().getStatusCode();
			if (code == 401 || code == 403) {
				// Access token is invalid or expired.Regenerate the access token
				System.out.println("Access token is invalid or expired. Regenerating access token....");
				String accessToken = getAccessToken(oauthDetails);
				if (isValid(accessToken)) 
				{
					// update the access token
					oauthDetails.setAccessToken(accessToken);
					get.removeHeaders(OAuthConstants.AUTHORIZATION);
					get.addHeader(OAuthConstants.AUTHORIZATION,
					getAuthorizationHeaderForAccessToken(oauthDetails.getAccessToken()));
					get.releaseConnection();
					response = client.execute(get);
					code = response.getStatusLine().getStatusCode();
					if (code >= 400)
					{
						throw new RuntimeException("Could not access protected resource. Server returned http code: "+ code);
					}

				} 
				else 
				{
					throw new RuntimeException("Could not regenerate access token");
				}

			}
			//updateWithPatch(oauthDetails);
			handleResponse(response);

		} 
		catch (ClientProtocolException e) 
		{
			// TODO Auto-generated catch block
			e.printStackTrace();
		} 
		catch (IOException e) 
		{
			// TODO Auto-generated catch block
			e.printStackTrace();
		} 
		finally 
		{
			get.releaseConnection();
		}

	}

	//Gets the URl for the pack from JSON data
	public static String packUrl()
	{
		JSONParser parser = new JSONParser();
		String uri = "";
        try {
 
            Object obj = parser.parse(new FileReader("0000000004.json"));
 
            JSONObject jsonObject = (JSONObject) obj;
            
            String productcode = (String) jsonObject.get("ProductCode");
            String serialnumber = (String) jsonObject.get("SerialNumber");
            String batchid = (String) jsonObject.get("BatchId");
            String batchexpirydate = (String) jsonObject.get("BatchExpiryDate");
            
            JSONObject name = (JSONObject)jsonObject.get("_state");
            String _name = (String)name.get("_name");
            System.out.println(_name);
             
            uri = Verify(productcode, serialnumber,batchid,batchexpirydate).toString();
          
        } 
        catch (Exception e) { e.printStackTrace();}
        
        return uri;
        	
	}
	
	
	public static URIBuilder Verify(String productCode, String serialNumber, String batch, String expiry)
	{
		URIBuilder builder = null;
		
			try {
				builder = new URIBuilder("/product/gtin/"+ productCode + "/pack/"+ serialNumber);
				builder.addParameter("batch", batch);
				builder.addParameter("expiry", expiry);
			} catch (URISyntaxException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
			return builder;
	}
	
	public static String getAccessToken(OAuth2Details oauthDetails) 
	{
		HttpPost post = new HttpPost(oauthDetails.getAuthenticationServerUrl());
		String clientId = oauthDetails.getClientId();
		String clientSecret = oauthDetails.getClientSecret();
		String scope = oauthDetails.getScope();

		Map<String, String> oauthLoginResponse = null;
		List<BasicNameValuePair> parametersBody = new ArrayList<BasicNameValuePair>();
		
		parametersBody.add(new BasicNameValuePair(OAuthConstants.GRANT_TYPE,
				oauthDetails.getGrantType()));
		
		parametersBody.add(new BasicNameValuePair(OAuthConstants.CLIENT_ID, clientId));
		
		parametersBody.add(new BasicNameValuePair(OAuthConstants.CLIENT_SECRET, clientSecret));
		
		if (isValid(scope)) 
		{
			parametersBody.add(new BasicNameValuePair(OAuthConstants.SCOPE,scope));
		}

		DefaultHttpClient client = new DefaultHttpClient();
		HttpResponse response = null;
		String accessToken = null;
		
		try {
			post.setEntity(new UrlEncodedFormEntity(parametersBody, HTTP.UTF_8));

			response = client.execute(post);
			int code = response.getStatusLine().getStatusCode();
			
			if (code == OAuthConstants.HTTP_UNAUTHORIZED) 
			{
				System.out.println("Authorization server expects Basic authentication");
				// Add Basic Authorisation header
				post.addHeader(OAuthConstants.AUTHORIZATION,
						getBasicAuthorizationHeader(oauthDetails.getClientId(),
								oauthDetails.getClientSecret()));
				System.out.println("Retry with client credentials");
				post.releaseConnection();
				response = client.execute(post);
				code = response.getStatusLine().getStatusCode();
				
				if (code == 401 || code == 403) {
					System.out.println("Could not authenticate using client credentials.");
					throw new RuntimeException("Could not retrieve access token for client: " + oauthDetails.getClientId());	
				}

			}
				
			oauthLoginResponse = (Map<String, String>) new JSONParser().parse(EntityUtils.toString(response.getEntity()));
			 
			System.out.println();
			System.out.println("************************ Token Details ************************");
			for (Map.Entry<String, String> entry : oauthLoginResponse.entrySet()) 
			{
				System.out.println(String.format("  %s = %s", entry.getKey(),entry.getValue()));
			}
			
			accessToken = oauthLoginResponse.get(OAuthConstants.ACCESS_TOKEN);
				
		}catch (ClientProtocolException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			throw new RuntimeException();
		}catch (ParseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			throw new RuntimeException();
		}catch (org.json.simple.parser.ParseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			throw new RuntimeException();
		}catch (RuntimeException e) {
			System.out.println("Could not parse JSON response");
			throw e;
		}

		return accessToken;
	}

	public static Map handleResponse(HttpResponse response) {
		String contentType = OAuthConstants.JSON_CONTENT;
		
		if (response.getEntity().getContentType() != null) 
		{
			contentType = response.getEntity().getContentType().getValue();
		}
		
		if (contentType.contains(OAuthConstants.JSON_CONTENT)) 
		{
			return handleJsonResponse(response);
		} 
		else if (contentType.contains(OAuthConstants.URL_ENCODED_CONTENT)) 
		{
			return handleURLEncodedResponse(response);
		} 
		else if (contentType.contains(OAuthConstants.XML_CONTENT))
		{
			return handleXMLResponse(response);
		} 
		else{
			// Unsupported Content type
			throw new RuntimeException("Cannot handle "+ contentType
							+ " content type. Supported content types include JSON, XML and URLEncoded");
		}

	}

	public static Map handleJsonResponse(HttpResponse response) {
		Map<String, String> oauthLoginResponse = null;
	
		try {
			oauthLoginResponse = (Map<String, String>) new JSONParser()
					.parse(EntityUtils.toString(response.getEntity()));
		} catch (ParseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			throw new RuntimeException();
		} catch (org.json.simple.parser.ParseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			throw new RuntimeException();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			throw new RuntimeException();
		} catch (RuntimeException e) {
			System.out.println("Could not parse JSON response");
			throw e;
		}
		System.out.println();
		System.out.println("************************ Pack Verfication Result ************************");
		for (Map.Entry<String, String> entry : oauthLoginResponse.entrySet()) {
			System.out.println(String.format("  %s = %s", entry.getKey(),entry.getValue()));
		}
		return oauthLoginResponse;
	}

	public static Map handleURLEncodedResponse(HttpResponse response) {
		Map<String, Charset> map = Charset.availableCharsets();
		Map<String, String> oauthResponse = new HashMap<String, String>();
		Set<Map.Entry<String, Charset>> set = map.entrySet();
		Charset charset = null;
		HttpEntity entity = response.getEntity();

		System.out.println();
		System.out.println("********** Response Received **********");

		for (Map.Entry<String, Charset> entry : set) {
			System.out.println(String.format("  %s = %s", entry.getKey(),
					entry.getValue()));
			if (entry.getKey().equalsIgnoreCase(HTTP.UTF_8)) {
				charset = entry.getValue();
			}
		}

		try {
			List<NameValuePair> list = URLEncodedUtils.parse(
					EntityUtils.toString(entity), Charset.forName(HTTP.UTF_8));
			for (NameValuePair pair : list) {
				System.out.println(String.format("  %s = %s", pair.getName(),
						pair.getValue()));
				oauthResponse.put(pair.getName(), pair.getValue());
			}

		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			throw new RuntimeException("Could not parse URLEncoded Response");
		}

		return oauthResponse;
	}

	public static Map handleXMLResponse(HttpResponse response) {
		Map<String, String> oauthResponse = new HashMap<String, String>();
		try {

			String xmlString = EntityUtils.toString(response.getEntity());
			DocumentBuilderFactory factory = DocumentBuilderFactory
					.newInstance();
			DocumentBuilder db = factory.newDocumentBuilder();
			InputSource inStream = new InputSource();
			inStream.setCharacterStream(new StringReader(xmlString));
			Document doc = db.parse(inStream);

			System.out.println("********** Response Receieved **********");
			parseXMLDoc(null, doc, oauthResponse);
		} catch (Exception e) {
			e.printStackTrace();
			throw new RuntimeException(
					"Exception occurred while parsing XML response");
		}
		return oauthResponse;
	}

	public static void parseXMLDoc(Element element, Document doc,
			Map<String, String> oauthResponse) {
		NodeList child = null;
		if (element == null) {
			child = doc.getChildNodes();

		} else {
			child = element.getChildNodes();
		}
		for (int j = 0; j < child.getLength(); j++) {
			if (child.item(j).getNodeType() == org.w3c.dom.Node.ELEMENT_NODE) {
				org.w3c.dom.Element childElement = (org.w3c.dom.Element) child
						.item(j);
				if (childElement.hasChildNodes()) {
					System.out.println(childElement.getTagName() + " : "
							+ childElement.getTextContent());
					oauthResponse.put(childElement.getTagName(),
							childElement.getTextContent());
					parseXMLDoc(childElement, null, oauthResponse);
				}

			}
		}
	}

	public static String getAuthorizationHeaderForAccessToken(String accessToken) {
		return OAuthConstants.BEARER + " " + accessToken;
	}

	public static String getBasicAuthorizationHeader(String username,
			String password) {
		return OAuthConstants.BASIC + " "
				+ encodeCredentials(username, password);
	}

	public static String encodeCredentials(String username, String password) {
		String cred = username + ":" + password;
		String encodedValue = null;
		byte[] encodedBytes = Base64.encodeBase64(cred.getBytes());
		encodedValue = new String(encodedBytes);
		System.out.println("encodedBytes " + new String(encodedBytes));

		byte[] decodedBytes = Base64.decodeBase64(encodedBytes);
		System.out.println("decodedBytes " + new String(decodedBytes));

		return encodedValue;

	}
	
	public static boolean isValidInput(OAuth2Details input)
	{		
		if(input == null){
			return false;
		}
		
		String grantType = input.getGrantType();
		
		if(!isValid(grantType)){
			System.out.println("Please provide valid value for grant_type");
			return false;
		}
		
		if(!isValid(input.getAuthenticationServerUrl())){
			System.out.println("Please provide valid value for authentication server url");
			return false;
		}
		
		if(grantType.equals(OAuthConstants.GRANT_TYPE_PASSWORD)){
			if(!isValid(input.getUsername()) || !isValid(input.getPassword())){
				System.out.println("Please provide valid username and password for password grant_type");
				return false;
			}
		}
		
		if(grantType.equals(OAuthConstants.GRANT_TYPE_CLIENT_CREDENTIALS)){
			if(!isValid(input.getClientId()) || !isValid(input.getClientSecret())){
				System.out.println("Please provide valid client_id and client_secret for client_credentials grant_type");
				return false;
			}
		}
		
		System.out.println("Validated Input");
		return true;
		
	}

	public static boolean isValid(String str) {
		return (str != null && str.trim().length() > 0);
	}

	public static void updateWithPatch(OAuth2Details oauthDetails)
	{
		JSONParser parser = new JSONParser();
		Object obj = null;
		try {
			obj = parser.parse(new FileReader("0000000004.json"));
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (org.json.simple.parser.ParseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
        JSONObject jsonObject = (JSONObject) obj;
        JSONObject name = (JSONObject)jsonObject.get("_state");
 		
		String payload ="{" + "  \"_state\":{" + "  \"_name\":" + "     \"Supplied" + "}";
		String resourceURL = oauthDetails.getResourceServerUrl();
	    HttpPatch httpPatch = new HttpPatch(resourceURL + packUrl());
	    try {
			httpPatch.setEntity(new StringEntity(payload, OAuthConstants.JSON_CONTENT));
			
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	    //httpSend(httpPatch, 204);
	   // response = httpGET(baseURL + "/People('kristakemp')", 200);
		
		
		
		
	}
}
