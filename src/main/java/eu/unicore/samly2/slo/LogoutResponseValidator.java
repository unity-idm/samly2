/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.unicore.samly2.slo;

import java.security.PublicKey;
import java.util.List;
import java.util.function.Function;

import eu.unicore.samly2.SAMLConstants;
import eu.unicore.samly2.exceptions.SAMLRequesterException;
import eu.unicore.samly2.exceptions.SAMLValidationException;
import eu.unicore.samly2.messages.SAMLVerifiableMessage;
import eu.unicore.samly2.trust.MessagePublicKeyTrustChecker;
import eu.unicore.samly2.validators.CommonResponseValidator;
import xmlbeans.org.oasis.saml2.assertion.NameIDType;
import xmlbeans.org.oasis.saml2.protocol.LogoutResponseDocument;
import xmlbeans.org.oasis.saml2.protocol.StatusResponseType;

/**
 * Validates SAML Logout Response, obtained after the SAML Logout request. 
 * 
 * @author K. Benedyczak
 */
public class LogoutResponseValidator
{
	private final CommonResponseValidator coreValidator;
	private final MessagePublicKeyTrustChecker trustChecker;
	
	public LogoutResponseValidator(String consumerEndpointUri, String requestId, 
			Function<NameIDType, List<PublicKey>> trustedKeysProvider)
	{
		coreValidator = new CommonResponseValidator(consumerEndpointUri, requestId);
		trustChecker = new MessagePublicKeyTrustChecker(trustedKeysProvider);
	}

	public void validate(LogoutResponseDocument logoutResponseDoc, SAMLVerifiableMessage verifiableMessage) throws SAMLValidationException
	{
		StatusResponseType response = logoutResponseDoc.getLogoutResponse();
		coreValidator.validate(logoutResponseDoc, response);
		validateIssuerType(response);
		verifyTrust(verifiableMessage, response);
	}

	private void verifyTrust(SAMLVerifiableMessage verifiableMessage, StatusResponseType response)
			throws SAMLRequesterException
	{
		try
		{
			trustChecker.verify(response.getIssuer(), verifiableMessage);
		} catch (SAMLValidationException e)
		{
			throw new SAMLRequesterException("SLO response is not trusted", e);
		}
	}
	
	private void validateIssuerType(StatusResponseType response) throws SAMLValidationException
	{
		NameIDType issuer = response.getIssuer();
		if (issuer != null)
		{
			if (issuer.getFormat() != null && !issuer.getFormat().equals(SAMLConstants.NFORMAT_ENTITY))
				throw new SAMLValidationException("Issuer of SAML response must be of "
						+ "Entity type in SSO AuthN. It is: " + issuer.getFormat());
		} else
			throw new SAMLValidationException("Issuer of SAML response is not set");
	}
}
