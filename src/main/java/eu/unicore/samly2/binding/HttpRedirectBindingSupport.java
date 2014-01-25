/*
 * Copyright (c) 2014 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.samly2.binding;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.Inflater;
import java.util.zip.InflaterOutputStream;

import org.bouncycastle.util.encoders.Base64;


/**
 * Helper class supporting SAML HTTP Redirect binding.
 * <p>
 * This implementation as of now doesn't support URL signing. However this feature shouldn't be used according
 * to the SAML interoperability profile http://saml2int.org/profile/current.
 * <p>
 * This implementation doesn't perform sanity checks on the input. Therefore it should be externally guaranteed
 * that the input string is a correct SAML protocol message and that neither it nor possibly included assertions
 * are signed.
 * @author K. Benedyczak
 */
public class HttpRedirectBindingSupport
{
	/**
	 * Produces a redirect URL with encoded SAML message.
	 * @param messageType whether the argument is request or response
	 * @param relayState relay state or null if not needed.
	 * @param samlMessage the saml protocol message encoded as string 
	 * @param samlParticipantURL the base URL of the SAML receiver
	 * @return
	 * @throws IOException 
	 * @throws  
	 */
	public static String getRedirectURL(SAMLMessageType messageType, String relayState, 
			String samlMessage, String samlParticipantURL) throws IOException
	{
		try
		{
			String samlParam = toURLParam(samlMessage);
			String samlParamEncoded = URLEncoder.encode(samlParam, "UTF-8");
			StringBuilder ret = new StringBuilder(samlParticipantURL);
			ret.append("?").append(messageType.toString()).append("=").append(samlParamEncoded);
			if (relayState != null)
			{
				String relayStateEncoded = URLEncoder.encode(relayState, "UTF-8");
				ret.append("&RelayState=").append(relayStateEncoded);
			}
			return ret.toString();
		} catch (Exception e)
		{
			throw new IOException("Problem encoding SAML redirect. Incorrect SAML receiver URL?", e);
		}
	}
	
	
	/**
	 * Creates a URL parameter to be used in redirect URL.
	 * The resulting string is deflated and base64 encoded, however it is not URL-encoded. 
	 * @param samlMessage
	 * @return
	 * @throws IOException 
	 * @throws UnsupportedEncodingException 
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
		String base64String = new String(base64Encoded, "UTF-8"); 
		return base64String;
	}

	/**
	 * Reversed {@link #toURLParam(String)}.
	 * @param samlRequest value of the URL parameter with the SAML assertion. It is assumed that the value was
	 * already URL decoded.
	 * @return String after Base64 decoding and decompression.
	 * @throws IOException
	 */
	public static String inflateSAMLRequest(String samlRequest) throws IOException
	{
		byte[] third = Base64.decode(samlRequest);
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
