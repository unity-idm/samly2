/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.unicore.samly2.validators;

import java.util.Calendar;

import xmlbeans.org.oasis.saml2.assertion.NameIDType;
import xmlbeans.org.oasis.saml2.protocol.LogoutRequestDocument;
import xmlbeans.org.oasis.saml2.protocol.LogoutRequestType;
import eu.unicore.samly2.exceptions.SAMLRequesterException;
import eu.unicore.samly2.exceptions.SAMLServerException;
import eu.unicore.samly2.trust.SamlTrustChecker;

/**
 * Validates SAML Logout Request, in accordance with the core SAML profile. 
 * 
 * @author K. Benedyczak
 */
public class LogoutRequestValidator extends AbstractRequestValidator
{
	public LogoutRequestValidator(String consumerEndpointUri, SamlTrustChecker trustChecker,
			long requestValidity, ReplayAttackChecker replayChecker)
	{
		super(consumerEndpointUri, trustChecker, requestValidity, replayChecker);
	}

	public void validate(LogoutRequestDocument logoutRequestDoc) throws SAMLServerException
	{
		LogoutRequestType logoutRequest = logoutRequestDoc.getLogoutRequest();
		super.validate(logoutRequestDoc, logoutRequest);
		
		validateIssuer(logoutRequest);
		validateSubject(logoutRequest);
		
		Calendar c = logoutRequest.getNotOnOrAfter();
		if (c != null)
		{
			if (Calendar.getInstance().after(c))
				throw new SAMLRequesterException("Request has expired");
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
		NameIDType subject = logoutRequest.getNameID();
		if (subject == null)
			throw new SAMLRequesterException("Logged out entity name must be present in SLO request "
					+ "and only NameID is supported");
		if (subject.getStringValue() == null)
			throw new SAMLRequesterException("Logged out entity value must be present in SLO request");
	}
}
