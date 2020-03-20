package com.corppass.app.service;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.interfaces.RSAKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.Random;

import javax.servlet.http.HttpServletResponse;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.lang.JoseException;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.ResourceUtils;
import org.springframework.web.client.RestTemplate;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.Unirest;
import com.mashape.unirest.http.exceptions.UnirestException;



/**
 * 
 * Step 1:Prepare for  CorpPass Login and Consent (authorise API) (ref:  CorpPassController => ("/myinfopage") )
 * 
 * Step 2: Login with CorpPass Business Info (ref: https://uat.ndi-api.gov.sg/library/myinfobiz/resources-personas)
 * 
 * Step 3: Click `I AGREE` button to retrieve your data . Then you will get authorisation code 
 * 
 * Step 4: Call the Token API (with the authorisation code)
 * 
 * Step 5: Call the Entity-Person API (with the access token) .
 * 		(5.1) You will get JWE(Json Web Encryption) data .
 * 		(5.2) You must decrypt JWE to get entity-person data
 * 			
 *
 */

@Service

public class CorpPassService {

	@Value("${myinfo.privateKeyContent}")
	private String privateKeyContent;

	@Value("${myinfo.publicKeyContent}") // staging_myinfo_public_cert.cer //stg-demoapp-client-publiccert-2018.pem
	private String publicKeyContent;

	private String authLevel;
	private String authApiUrl;
	private String clientId;
	private String clientSecret;
	private String redirectUrl;
	private String attributes;
	private String purpose;
	private String realm;
	private String tokenApiUrl;
	private String personApiUrl;
	private String cacheCtl;
	private String contentType;
	private String method;





	public JSONObject getMyInfodata(String code) {
		
		System.out.println("****************************privae key *************** ");
		System.out.println(privateKeyContent);
		System.out.println("****************************public key *************** ");
		System.out.println(publicKeyContent);

		cacheCtl = "no-cache";
		contentType = "application/x-www-form-urlencoded";
		method = "POST";

		JSONObject entyty_person = null;

		// call general setting service to assign myinfo values
		if (code == null || code.isEmpty())
			code = "asdfghjkl;234567890"; // put wrong code if we not get correct code

		clientId = "STG2-MYINFO-SELF-TEST";
		clientSecret = "44d953c796cccebcec9bdc826852857ab412fbe2";
		realm = "http://localhost:3001";
		redirectUrl ="http://localhost:3001/callback";
		authLevel = "L2";

		authApiUrl = "https://test.api.myinfo.gov.sg/biz/v1/authorise";
		tokenApiUrl = "https://test.api.myinfo.gov.sg/biz/v1/token";
		personApiUrl = "https://test.api.myinfo.gov.sg/biz/v1/entity-person";

		attributes = "name,sex,race,nationality,dob,regadd,housingtype,email,mobileno,marital,edulevel,basic-profile,addresses,appointments";

		System.out.println("CODE => " + code);
		String authHeader = generateAuthorizationHeader(tokenApiUrl, method, contentType, authLevel, clientId,
				privateKeyContent, clientSecret, realm, code);

		try {
			HttpResponse<String> response = Unirest.post(tokenApiUrl)
					.header("Content-Type", "application/x-www-form-urlencoded").header("Cache-Control", "no-cache")
					.header("Authorization", authHeader).field("grant_type", "authorization_code").field("code", code)
					.field("redirect_uri", "http://localhost:3001/callback").field("client_id", "STG2-MYINFO-SELF-TEST")
					.field("client_secret", "44d953c796cccebcec9bdc826852857ab412fbe2").asString();

			System.out.println("RESPONSE TOKEN => " + response.getBody());
			if (response.getStatus() == 200) {
				System.out.println("status code is  " + response.getStatus());
				JSONObject tokenjson = new JSONObject(response.getBody().toString());
				String token = tokenjson.getString("access_token");
				System.out.println("to verfiy the token with public cer ..." + token);
				String sub = getNRICparam(token);

				if (null != sub) {

					String params = "client_id=" + clientId + "&attributes=" + attributes;
					
					
					String authHeaderForPerson = generateAuthorizationHeader(
						personApiUrl+ "/" + sub.replace("_", "/")+"/",
						    "GET",
						    "", // no content type needed for GET
						    "L2",
						    clientId,
						    privateKeyContent,
						    clientSecret,
						    realm,
						    ""
						  );
					
					System.out.println("************** auth header *********** ");
					System.out.println(authHeaderForPerson);
					personApiUrl += "/" + sub.replace("_", "/") + "/?" + params;
					String authorization = authHeaderForPerson + ",Bearer " + token;
					
					System.out.println("authorization >> "+authorization);
					
					

					HttpResponse<String> responsePerson = Unirest.get(personApiUrl)
							.header("Cache-Control", "no-cache")
							.header("Authorization",authorization)
							.asString();

					 entyty_person = new JSONObject(decryptJWE(responsePerson.getBody()));
					
					
					return entyty_person;
					
					

				}

			} else {
				System.out.println("status code is  " + response.getStatus());
			}

		} catch (UnirestException e) {
			System.out.println(e.getMessage());
		} catch (Exception e) {
			e.printStackTrace();
		}
		return entyty_person;


	}

	private String decryptJWE(String jwetoken) {
		String decrypted = new JSONObject().toString();
		System.out.println("JWE token " + jwetoken);
		try {
			// InputStream is = getClass().getResourceAsStream(privateKeyContent);
			FileInputStream fIS = new FileInputStream(ResourceUtils.getFile(privateKeyContent));
			/* InputStream is = new FileInputStream(privateKeyContent); */
			String privateKeySTr = IOUtils.toString(fIS, "UTF-8");
			PemObject pem = new PemReader(new StringReader(privateKeySTr)).readPemObject();
			PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(pem.getContent());
			KeyFactory kf = KeyFactory.getInstance("RSA");

			JsonWebEncryption jwe = new JsonWebEncryption();
			jwe.setKey(kf.generatePrivate(spec));
			try {
				jwe.setCompactSerialization(jwetoken);
				decrypted = jwe.getPayload();
			} catch (JoseException e) {
				e.printStackTrace();
			}

		} catch (Exception e) {
			e.printStackTrace();
		}
		return decrypted;
		
	}

	private String generateAuthorizationHeader(String url, String method, String contentType, String authLevel,
			String clientId, String privateKeyContent, String clientSecret, String realm, String code) {
		if (authLevel.equals("L2")) {
			return generateSHA256withRSAHeader(url, method, contentType, clientId, privateKeyContent,
					clientSecret, realm, code);
		} else {
			return "";
		}
	}

	private String generateSHA256withRSAHeader(String tokenApiUrl, String method, String contentType, String clientId,
			String privateKeyContent, String clientSecret, String realm, String code) {

		long nonceValue = nonce();
		System.out.println("NONCE VALUE => " + nonceValue);
		long timestamp = System.currentTimeMillis();
		System.out.println("TIME STAMP => " + timestamp);
		
		String baseParamsStr = "";
		
		if (code.isEmpty()) {
			System.out.println("********* base string for person api ************** ");
			baseParamsStr = "apex_l2_eg_app_id="+clientId+
							"&apex_l2_eg_nonce="+nonceValue+
							"&apex_l2_eg_signature_method="+"SHA256withRSA"+
							"&apex_l2_eg_timestamp="+timestamp+
							"&apex_l2_eg_version="+"1.0"+
							"&attributes="+attributes+
							"&client_id="+clientId;
			
			
		}else {
			System.out.println("********* base string for token api ************** ");
			baseParamsStr = "apex_l2_eg_app_id=" + clientId + "&" + "apex_l2_eg_nonce=" + nonceValue + "&"
					+ "apex_l2_eg_signature_method=SHA256withRSA&" + "apex_l2_eg_timestamp=" + timestamp + "&"
					+ "apex_l2_eg_version=1.0&" + "client_id=" + clientId + "&" + "client_secret=" + clientSecret + "&"
					+ "code=" + code + "&" + "grant_type=authorization_code&" + "redirect_uri=" + redirectUrl;
			
		}

		

		String replaceUrl = tokenApiUrl.replace(".api.gov.sg", ".e.api.gov.sg");

		String baseString = method.toUpperCase() + "&" + replaceUrl + "&" + baseParamsStr;
		System.out.println("defaultApexHeaders = " + baseString);

		String signature = getSignature(baseString);
		System.out.println("HERE SIGNATURE => " + signature);

		String strApexHeader = "apex_l2_eg realm=\"" + realm + "\",apex_l2_eg_timestamp=\"" + timestamp
				+ "\",apex_l2_eg_nonce=\"" + nonceValue + "\",apex_l2_eg_app_id=\"" + clientId
				+ "\",apex_l2_eg_signature_method=\"SHA256withRSA\"" + ",apex_l2_eg_version=\"1.0\""
				+ ",apex_l2_eg_signature=\"" + signature + "\"";
		System.out.println("STR APEX HEADER => " + strApexHeader);
		return strApexHeader;
	}

	private String getSignature(String baseString) {
		String signWithStr = "";
		PrivateKey privKey = null;
		File file = new File(privateKeyContent);
		try {

			BufferedReader br = new BufferedReader(new FileReader(file));

			String st;
			while ((st = br.readLine()) != null) {
				signWithStr = signWithStr + st;
			}
			br.close();
			signWithStr = signWithStr.replaceAll("\\n", "").replace("-----BEGIN PRIVATE KEY-----", "")
					.replace("-----END PRIVATE KEY-----", "");
			KeyFactory kf = KeyFactory.getInstance("RSA");
			PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(signWithStr));
			privKey = kf.generatePrivate(keySpecPKCS8);
			System.out.println("HERE PRIVATE KEY => " + privKey);

			// Creating a Signature object
			Signature sign = Signature.getInstance("SHA256withRSA");

			// Initialize the signature
			sign.initSign(privKey);

			byte[] bytes = baseString.getBytes();
			// Adding data to the signature
			sign.update(bytes);

			// Calculating the signature
			byte[] signature = sign.sign();

			return Base64.getEncoder().encodeToString(signature);
		} catch (NoSuchAlgorithmException e) {
			System.out.println(e.getMessage());
		} catch (InvalidKeyException ivke) {
			System.out.println(ivke.getMessage());
		} catch (SignatureException se) {
			System.out.println(se.getMessage());
		} catch (FileNotFoundException fne) {
			System.out.println(fne.getMessage());
		} catch (InvalidKeySpecException ivkse) {
			System.out.println(ivkse.getMessage());
		} catch (IOException ioe) {
			System.out.println(ioe.getMessage());
		}
		return null;
	}

	private long nonce() {
		Random rand;
		try {
			rand = SecureRandom.getInstance("SHA1PRNG");
			return rand.nextLong();
		} catch (NoSuchAlgorithmException e) {
			System.out.println(e.getMessage());
		}
		return 0;
	}

	public String getNRICparam(String jwtToken) {

		try {
			CertificateFactory fact = CertificateFactory.getInstance("X.509");
			FileInputStream fIS = new FileInputStream(ResourceUtils.getFile(publicKeyContent));
			Certificate cer = fact.generateCertificate(fIS);
			PublicKey key = cer.getPublicKey();
			System.out.println("get the public key ");
			System.out.println("key is ....." + key);
			System.out.println("Token " + jwtToken);
			JWTVerifier verifier = JWT.require(Algorithm.RSA256((RSAKey) key)).acceptNotBefore(60).acceptLeeway(60)
					.build();
			System.out.println("before verify token...");
			DecodedJWT jwt2 = verifier.verify(jwtToken);

			String uinfin = jwt2.getSubject();
			System.out.println("uinfin..." + uinfin);

			return uinfin;
		} catch (CertificateException e) {
			System.out.println("in CertificateException");
			e.printStackTrace();
		} catch (Exception e) {
			System.out.println("in Exception");
			e.printStackTrace();
		}

		return null;
	}

}

