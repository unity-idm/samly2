/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.unicore.samly2.slo;

import java.security.PublicKey;
import java.util.Calendar;
import java.util.List;
import java.util.function.Function;

import eu.unicore.samly2.exceptions.SAMLRequesterException;
import eu.unicore.samly2.exceptions.SAMLServerException;
import eu.unicore.samly2.exceptions.SAMLValidationException;
import eu.unicore.samly2.messages.SAMLVerifiableElement;
import eu.unicore.samly2.trust.SignatureChecker;
import eu.unicore.samly2.validators.CommonRequestValidation;
import eu.unicore.samly2.validators.ReplayAttackChecker;
import xmlbeans.org.oasis.saml2.assertion.NameIDType;
import xmlbeans.org.oasis.saml2.protocol.LogoutRequestDocument;
import xmlbeans.org.oasis.saml2.protocol.LogoutRequestType;

/**
 * Validates SAML Logout Request, in accordance with the core SAML profile. 
 * 
 * @author K. Benedyczak
 */
public class LogoutRequestValidator
{
	private final CommonRequestValidation commonValidator;
	private final SignatureChecker signatureChecker;
	
	public LogoutRequestValidator(String consumerEndpointUri, long requestValidity, ReplayAttackChecker replayChecker, 
			Function<NameIDType, List<PublicKey>> trustedKeysProvider)
	{
		commonValidator = new CommonRequestValidation(consumerEndpointUri, requestValidity, replayChecker);
		signatureChecker = new SignatureChecker(trustedKeysProvider);
	}

	public void validate(LogoutRequestDocument logoutRequestDoc, SAMLVerifiableElement verifiableMessage) 
			throws SAMLServerException
	{
		LogoutRequestType logoutRequest = logoutRequestDoc.getLogoutRequest();
		commonValidator.validateBasicElements(logoutRequest);
		verifyTrust(verifiableMessage, logoutRequest);
		commonValidator.validateReply(logoutRequest);
		
		validateIssuer(logoutRequest);
		validateSubject(logoutRequest);
		
		Calendar c = logoutRequest.getNotOnOrAfter();
		if (c != null)
		{
			if (Calendar.getInstance().after(c))
				throw new SAMLRequesterException("Request has expired");
		}
	}

	private void verifyTrust(SAMLVerifiableElement verifiableMessage, LogoutRequestType logoutRequest)
			throws SAMLRequesterException
	{
		try
		{
			signatureChecker.verify(logoutRequest.getIssuer(), verifiableMessage);
		} catch (SAMLValidationException e)
		{
			throw new SAMLRequesterException("Request is not trusted", e);
		}
	}
	
	protected void validateIssuer(LogoutRequestType logoutRequest) throws SAMLServerException
	{
		NameIDType issuer = logoutRequest.getIssuer();
		if (issuer == null)
			throw new SAMLRequesterException("Issuer of SAML request must be present in SLO");
/* Actually this test should be enabled here. But with it UNICORE services won't be able to use SLO. 
 * This check lift should be in the unicore module. But require tons of code, and this simple patch here 
 * shouldn't break anything.
 * 		if (issuer.getFormat() != null && !issuer.getFormat().equals(SAMLConstants.NFORMAT_ENTITY))
			throw new SAMLRequesterException("Issuer of SAML request must be of Entity type in SLO. "
					+ "It is: " + issuer.getFormat());*/
		if (issuer.getStringValue() == null)
			throw new SAMLRequesterException("Issuer of SAML request value must be present in SLO");
	}
	
	protected void validateSubject(LogoutRequestType logoutRequest) throws SAMLServerException
	{
		NameIDType plainSubject = logoutRequest.getNameID();
		if (plainSubject != null)
		{
			if (plainSubject.getStringValue() == null)
				throw new SAMLRequesterException("Logged out entity value must be present in SLO request");
			return;
		}
		if (logoutRequest.getEncryptedID() != null)
			return;
		throw new SAMLRequesterException("Logged out entity name must be present in SLO request "
				+ "and only NameID or EncryptedID are supported");
	}
}
