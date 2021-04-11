/*
 * Copyright (c) 2021 Bixbit - Krzysztof Benedyczak. All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.samly2.trust;

import static eu.unicore.samly2.trust.CheckingMode.REQUIRE_SIGNED_RESPONSE_OR_ASSERTION;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;
import static org.mockito.Mockito.mock;

import java.security.PublicKey;

import org.junit.Test;

import eu.unicore.samly2.SAMLConstants;
import eu.unicore.samly2.exceptions.SAMLValidationException;
import eu.unicore.samly2.messages.SAMLVerifiableElement;
import xmlbeans.org.oasis.saml2.assertion.NameIDType;
import xmlbeans.org.oasis.saml2.protocol.AuthnRequestType;
import xmlbeans.org.oasis.saml2.protocol.RequestAbstractType;

public class StrictTrustCheckerTest
{
	private PublicKey pk1 = mock(PublicKey.class);
	private NameIDType name = getIssuerName();
	
	@Test
	public void shouldAcceptSignedRequestWithDetachedSignature()
	{
		StrictSamlTrustChecker strictChecker = new StrictSamlTrustChecker(REQUIRE_SIGNED_RESPONSE_OR_ASSERTION);
		strictChecker.addTrustedIssuer("issuer", SAMLConstants.NFORMAT_ENTITY, pk1);

		RequestAbstractType req = AuthnRequestType.Factory.newInstance();
		req.setIssuer(name);
		SAMLVerifiableElement verifiableElement = new FakeVerifiableElement(pk1, true, pk -> {});
		
		Throwable error = catchThrowable(() -> strictChecker.checkTrust(verifiableElement, req));
		
		assertThat(error).isNull();
	}

	@Test
	public void shouldDenyUnsignedRequest()
	{
		StrictSamlTrustChecker strictChecker = new StrictSamlTrustChecker(REQUIRE_SIGNED_RESPONSE_OR_ASSERTION);
		strictChecker.addTrustedIssuer("issuer", SAMLConstants.NFORMAT_ENTITY, pk1);

		RequestAbstractType req = AuthnRequestType.Factory.newInstance();
		req.setIssuer(name);
		SAMLVerifiableElement verifiableElement = new FakeVerifiableElement(pk1, false, pk -> {});
		
		Throwable error = catchThrowable(() -> strictChecker.checkTrust(verifiableElement, req));
		
		assertThat(error).isInstanceOf(SAMLValidationException.class).hasMessageContaining("not signed");
	}
	
	private static NameIDType getIssuerName()
	{
		NameIDType name = NameIDType.Factory.newInstance();
		name.setFormat(SAMLConstants.NFORMAT_ENTITY);
		name.setStringValue("issuer");
		return name;
	}
}
