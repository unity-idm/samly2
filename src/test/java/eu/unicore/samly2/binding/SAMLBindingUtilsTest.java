/*
 * Copyright (c) 2014 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.samly2.binding;

import static eu.unicore.samly2.binding.HttpRedirectBindingSupport.verifyDocumentSigature;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

import java.net.URI;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import org.junit.Assert;
import org.junit.Test;

import eu.unicore.security.dsig.DSigException;
import eu.unicore.security.dsig.TestBase;


public class SAMLBindingUtilsTest
{
	@Test
	public void encodingAndDecodingDoesntChangeMessage() throws Exception
	{
		String a = "someString~!@#$%^&*(\u0001\u0002\u0003\u0010\u2222";
		Assert.assertEquals(a, HttpRedirectBindingSupport.inflateSAMLRequest(
				HttpRedirectBindingSupport.toURLParam(a)));
	}
	
	@Test
	public void generatedSignaturePassesValidation() throws Exception
	{
		KeyStore ks1 = TestBase.loadKeystore(TestBase.KEYSTORE1);
		X509Certificate[] certificate = TestBase.convertChain(ks1.getCertificateChain(TestBase.ALIAS));
		PrivateKey privKey1 = (PrivateKey) ks1.getKey(TestBase.ALIAS, TestBase.PASSWORD.toCharArray());
		
		String doc = "some-pseudo-saml-doc";
		
		String urlString = HttpRedirectBindingSupport.getSignedRedirectURL(SAMLMessageType.SAMLRequest, "relay", doc, 
				"https://base-url", privKey1);
		
		URI url = new URI(urlString);
		
		Throwable error = catchThrowable(() -> verifyDocumentSigature(
				url.getRawQuery(), certificate[0].getPublicKey()));
		assertThat(error).isNull();
	}

	@Test
	public void generatedSignatureWithoutRelayPassesValidation() throws Exception
	{
		KeyStore ks1 = TestBase.loadKeystore(TestBase.KEYSTORE1);
		X509Certificate[] certificate = TestBase.convertChain(ks1.getCertificateChain(TestBase.ALIAS));
		PrivateKey privKey1 = (PrivateKey) ks1.getKey(TestBase.ALIAS, TestBase.PASSWORD.toCharArray());
		
		String doc = "some-pseudo-saml-doc";
		
		String urlString = HttpRedirectBindingSupport.getSignedRedirectURL(SAMLMessageType.SAMLRequest, null, doc, 
				"https://base-url", privKey1);
		
		URI url = new URI(urlString);
		
		Throwable error = catchThrowable(() -> verifyDocumentSigature(
				url.getRawQuery(), certificate[0].getPublicKey()));
		assertThat(error).isNull();
	}
	
	@Test
	public void malformedSignatureFailsAtValidation() throws Exception
	{
		KeyStore ks1 = TestBase.loadKeystore(TestBase.KEYSTORE1);
		X509Certificate[] certificate = TestBase.convertChain(ks1.getCertificateChain(TestBase.ALIAS));
		PrivateKey privKey1 = (PrivateKey) ks1.getKey(TestBase.ALIAS, TestBase.PASSWORD.toCharArray());
		
		String doc = "some-pseudo-saml-doc";
		
		String urlString = HttpRedirectBindingSupport.getSignedRedirectURL(SAMLMessageType.SAMLRequest, "relay", doc, 
				"https://base-url", privKey1);
		
		String malformedString = urlString.replace("RelayState=relay", "RelayState=relayCHANGED");
		
		URI url = new URI(malformedString);
		Throwable error = catchThrowable(() -> verifyDocumentSigature(
				url.getRawQuery(), certificate[0].getPublicKey()));
		
		assertThat(error).isInstanceOf(DSigException.class);
	}
}
