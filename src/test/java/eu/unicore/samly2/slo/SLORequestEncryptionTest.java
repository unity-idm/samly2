/*
 * Copyright (c) 2019 Bixbit - Krzysztof Benedyczak. All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.samly2.slo;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.mock;

import org.apache.xmlbeans.XmlOptions;
import org.junit.Test;

import eu.unicore.samly2.SAMLConstants;
import eu.unicore.samly2.elements.NameID;
import eu.unicore.samly2.proto.LogoutRequest;
import eu.unicore.samly2.trust.SamlTrustChecker;
import eu.unicore.samly2.validators.LogoutRequestValidator;
import eu.unicore.samly2.validators.ReplayAttackChecker;
import eu.unicore.security.dsig.TestBase;
import xmlbeans.org.oasis.saml2.assertion.NameIDType;
import xmlbeans.org.oasis.saml2.protocol.LogoutRequestDocument;

public class SLORequestEncryptionTest extends TestBase
{
	@Test
	public void shouldDecryptEncryptedSubject() throws Exception
	{
		NameIDType issuer = new NameID("issuer", SAMLConstants.NFORMAT_ENTITY).getXBean();
		NameIDType subject = new NameID("subject", SAMLConstants.NFORMAT_ENTITY).getXBean();
		LogoutRequest request = new LogoutRequest(issuer, subject);
		request.encryptSubject(issuerCert1[0].getPublicKey(), 256);
		
		LogoutRequestDocument encryptedRequest = request.getXMLBeanDoc();
		
		System.out.println("Encrypted:\n" + encryptedRequest.xmlText(new XmlOptions().setSavePrettyPrint()) + "\n");
		
		LogoutRequestValidator validator = new LogoutRequestValidator(
				"consumerEndpoint", mock(SamlTrustChecker.class), 1000000l, mock(ReplayAttackChecker.class));
		LogoutRequestParser parser = new LogoutRequestParser(validator, privKey1);
		ParsedLogoutRequest parsedRequest = parser.parseRequest(encryptedRequest);
		
		assertThat(parsedRequest.getIssuer().xmlText(), is(issuer.xmlText()));
		assertThat(parsedRequest.getSubject().xmlText(), is(subject.xmlText()));
	}
	
	@Test
	public void shouldEncryptSubject() throws Exception
	{
		NameIDType issuer = new NameID("issuer", SAMLConstants.NFORMAT_ENTITY).getXBean();
		NameIDType subject = new NameID("subject", SAMLConstants.NFORMAT_ENTITY).getXBean();
		LogoutRequest request = new LogoutRequest(issuer, subject);
		request.encryptSubject(issuerCert1[0].getPublicKey(), 128);
		
		LogoutRequestDocument encryptedRequest = request.getXMLBeanDoc();
		
		assertThat(encryptedRequest.getLogoutRequest().getNameID(), is(nullValue()));
		assertThat(encryptedRequest.getLogoutRequest().getEncryptedID(), is(not(nullValue())));
	}
}