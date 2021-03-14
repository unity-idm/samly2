/*
 * Copyright (c) 2014 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.samly2.binding;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.HashMap;
import java.util.Map;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.Inflater;
import java.util.zip.InflaterOutputStream;

import org.bouncycastle.util.encoders.Base64;

import eu.unicore.security.dsig.DSigException;
import eu.unicore.security.dsig.DigSignatureUtil;


/**
 * Helper class supporting SAML HTTP Redirect binding.
 * <p>
 * This implementation doesn't perform sanity checks on the input. Therefore it should be externally guaranteed
 * that the input string is a correct SAML protocol message and that possibly included assertions are not signed.
 * @author K. Benedyczak
 */
public class HttpRedirectBindingSupport
{
	public static final String SIGNATURE_ALGORITHM_PARAM = "SigAlg";
	public static final String SIGNATURE_PARAM = "Signature";
	public static final String RELAY_STATE_PARAM = "RelayState";
	
	
	/**
	 * Produces a redirect URL with encoded SAML message.
	 * @param messageType whether the argument is request or response
	 * @param relayState relay state or null if not needed.
	 * @param samlMessage the saml protocol message encoded as string 
	 * @param samlParticipantURL the base URL of the SAML receiver
	 */
	public static String getRedirectURL(SAMLMessageType messageType, String relayState, 
			String samlMessage, String samlParticipantURL) throws IOException
	{
		String plainQueryString = buildPlainRedirectQueryString(messageType, relayState, samlMessage);
		return buildFinalURL(samlParticipantURL, plainQueryString);
	}

	/**
	 * Produces a signed redirect URL with encoded SAML message.
	 * @param messageType whether the argument is request or response
	 * @param relayState relay state or null if not needed.
	 * @param samlMessage the saml protocol message encoded as string, without any signature
	 * @param samlParticipantURL the base URL of the SAML receiver
	 */
	public static String getSignedRedirectURL(SAMLMessageType messageType, String relayState, 
			String samlMessage, String samlParticipantURL, PrivateKey signingKey) 
					throws IOException, DSigException
	{
		
		String plainQueryString = buildPlainRedirectQueryString(messageType, relayState, samlMessage);
		String signedQueryString = signQuery(plainQueryString, signingKey);
		return buildFinalURL(samlParticipantURL, signedQueryString);
	}

	private static String signQuery(String plainQueryString, PrivateKey signingKey) 
			throws DSigException
	{
		try
		{
			String algorithmName = DigSignatureUtil.getSAMLSignatureAlgorithmForPrivateKey(signingKey);
			String queryStringToSign = plainQueryString + "&" + SIGNATURE_ALGORITHM_PARAM + "=" 
					+ urlEncode(algorithmName);
			String signatureValue = signString(queryStringToSign, signingKey);
			return queryStringToSign + "&" + SIGNATURE_PARAM + "=" + urlEncode(signatureValue);
		} catch (Exception e)
		{
			throw new DSigException("Signing redirect URL query failed", e);
		}
	}

	private static String signString(String message, PrivateKey signingKey) 
			throws NoSuchAlgorithmException, SignatureException, KeyException
	{
		String signatureAlgorithm = DigSignatureUtil.getJCASignatureAlgorithmForPrivateKey(signingKey);
		Signature signature = Signature.getInstance(signatureAlgorithm);
		signature.initSign(signingKey);
		signature.update(message.getBytes(StandardCharsets.UTF_8));
		byte[] signedBytes = signature.sign();
		byte[] base64Encoded = Base64.encode(signedBytes);
		return new String(base64Encoded, StandardCharsets.UTF_8);
	}
	
	private static String buildPlainRedirectQueryString(SAMLMessageType messageType, String relayState, 
			String samlMessage) throws IOException
	{
		try
		{
			String samlParam = toURLParam(samlMessage);
			return buildBaseURLStringWithEncoding(messageType, samlParam, relayState);
		} catch (Exception e)
		{
			throw new IOException("Problem encoding SAML redirect. Incorrect SAML receiver URL?", e);
		}
	}

	private static String buildFinalURL(String samlParticipantURL, String queryPart)
	{
		return samlParticipantURL + "?" + queryPart;
	}
	
	/**
	 * Creates a URL parameter to be used in redirect URL.
	 * The resulting string is deflated and base64 encoded, however it is not URL-encoded. 
	 */
	public static String toURLParam(String samlMessage) throws UnsupportedEncodingException, IOException
	{
		Deflater deflater = new Deflater(5, true);
		ByteArrayOutputStream baos = new ByteArrayOutputStream(1024);
		DeflaterOutputStream deflateOS = new DeflaterOutputStream(baos, deflater);
		deflateOS.write(samlMessage.getBytes("UTF-8"));
		deflateOS.flush();
		deflateOS.close();
		
		byte[] base64Encoded = Base64.encode(baos.toByteArray());
		return new String(base64Encoded, "UTF-8"); 
	}


	/**
	 * Verifies the signature of SAML document, as extracted from the redirect binding URL.
	 * @param encodedDocument response or request document as obtained from URL query parameter
	 * @param algorithm signature algorithm as obtained from URL query parameter
	 * @param signatureValue signature value as obtained from URL query parameter
	 * @param verificationKey verification public key
	 */
	public static void verifyDocumentSigature(String rawQueryString, PublicKey verificationKey) throws DSigException
	{
		Map<String, String> paramsMap = parseQueryString(rawQueryString);
		SAMLMessageType messageType = getMessageType(paramsMap);
		String rawEncodedDocument = paramsMap.get(messageType.toString());
		String rawRelayState = paramsMap.get(RELAY_STATE_PARAM);
		String rawAlgorithm = getMandatoryParam(paramsMap, SIGNATURE_ALGORITHM_PARAM);
		String plainQueryString = buildBaseURLStringNoEncoding(messageType, rawEncodedDocument, rawRelayState);
		String queryStringToCheck = plainQueryString + "&" + SIGNATURE_ALGORITHM_PARAM + "=" + rawAlgorithm;
		try
		{
			String algorithm = urlDecode(rawAlgorithm);
			String signatureValueBase64 = urlDecode(getMandatoryParam(paramsMap, SIGNATURE_PARAM));
			byte[] signatureValue = Base64.decode(signatureValueBase64.getBytes(StandardCharsets.UTF_8));
			String jcaAlgorithm = DigSignatureUtil.getJCASignatureAlgorithmForSAMLSignatureAlgorithm(algorithm);
			Signature signature = Signature.getInstance(jcaAlgorithm);
			signature.initVerify(verificationKey);
			signature.update(queryStringToCheck.getBytes(StandardCharsets.UTF_8));
			if (!signature.verify(signatureValue))
				throw new DSigException("Document signature is invalid");
		} catch (SignatureException | NoSuchAlgorithmException | KeyException e)
		{
			throw new DSigException("Error during document digital signature verification", e);
		}		
	}

	public static boolean isSigned(String rawQueryString)
	{
		Map<String, String> paramsMap = parseQueryString(rawQueryString);
		return paramsMap.get(SIGNATURE_ALGORITHM_PARAM) != null && paramsMap.get(SIGNATURE_PARAM) != null;
	}
	
	private static SAMLMessageType getMessageType(Map<String, String> paramsMap) 
	{
		if (paramsMap.containsKey(SAMLMessageType.SAMLRequest.toString()))
			return SAMLMessageType.SAMLRequest;
		if (paramsMap.containsKey(SAMLMessageType.SAMLResponse.toString()))
				return SAMLMessageType.SAMLResponse;
		throw new IllegalArgumentException("Neither SAMLRequest nor SAMLResponse present in SAML URL query string");
	}
	
	private static String getMandatoryParam(Map<String, String> paramsMap, String param) 
	{
		String value = paramsMap.get(param);
		if (value == null)
			throw new IllegalArgumentException("Mandatory parameter " + param + " not present in SAML URL query string");
		return value;
	}
	
	
	private static Map<String, String> parseQueryString(String rawQueryString)
	{
		String[] params = rawQueryString.split("&");
		Map<String, String> parsedParams = new HashMap<>();
		for (String rawParam: params)
		{
			int splitIndex = rawParam.indexOf("=");
			if (splitIndex == -1)
				throw new IllegalArgumentException("Illegal SAML redirect query string, includes "
						+ "parameter without value: " + rawParam);
			String paramName = rawParam.substring(0, splitIndex);
			String paramValue = splitIndex == rawParam.length() - 1 ? "" : rawParam.substring(splitIndex + 1);
			parsedParams.put(paramName, paramValue);
		}
		return parsedParams;
	}
	
	private static String buildBaseURLStringWithEncoding(SAMLMessageType messageType, String encodedDocument, 
			String relayState)
	{
		return buildBaseURLStringNoEncoding(messageType, urlEncode(encodedDocument), 
				relayState == null ? null : urlEncode(relayState));
	}
	
	private static String buildBaseURLStringNoEncoding(SAMLMessageType messageType, String encodedDocument, 
			String relayState)
	{
		StringBuilder ret = new StringBuilder();
		ret.append(messageType.toString()).append("=").append(encodedDocument);
		if (relayState != null)
		{
			ret.append("&").append(RELAY_STATE_PARAM).append("=").append(relayState);
		}
		return ret.toString();
	}
	
	private static String urlEncode(String rawValue)
	{
		try 
		{
			return URLEncoder.encode(rawValue, "UTF-8");
		} catch (UnsupportedEncodingException e) 
		{
			throw new IllegalStateException("UTF-8 should not be unsupported, but seems so?", e);
		}
	}
	
	private static String urlDecode(String rawValue)
	{
		try 
		{
			return URLDecoder.decode(rawValue, "UTF-8");
		} catch (UnsupportedEncodingException e) 
		{
			throw new IllegalStateException("UTF-8 should not be unsupported, but seems so?", e);
		}
	}
	
	/**
	 * Reversed {@link #toURLParam(String)}.
	 * @param encodedSAMLDocument value of the URL parameter with the SAML assertion. It is assumed that the value was
	 * already URL decoded.
	 * @return String after Base64 decoding and decompression, containing text representation of SAML document.
	 */
	public static String inflateSAMLRequest(String encodedSAMLDocument) throws IOException
	{
		byte[] third = Base64.decode(encodedSAMLDocument);
		Inflater decompressor = new Inflater(true);
		decompressor.setInput(third, 0, third.length);
		ByteArrayOutputStream baos = new ByteArrayOutputStream(1024);
		InflaterOutputStream os = new InflaterOutputStream(baos, decompressor);
		os.write(third);
		os.finish();
		os.close();
		return new String(baos.toByteArray(), "UTF-8");
	}
}
