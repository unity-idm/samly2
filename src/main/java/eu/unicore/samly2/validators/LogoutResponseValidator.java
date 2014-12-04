/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.unicore.samly2.validators;

import xmlbeans.org.oasis.saml2.assertion.NameIDType;
import xmlbeans.org.oasis.saml2.protocol.LogoutResponseDocument;
import xmlbeans.org.oasis.saml2.protocol.StatusResponseType;
import eu.unicore.samly2.SAMLConstants;
import eu.unicore.samly2.exceptions.SAMLValidationException;
import eu.unicore.samly2.trust.SamlTrustChecker;

/**
 * Validates SAML Logout Response, obtained after the SAML Logout request. 
 * 
 * @author K. Benedyczak
 */
public class LogoutResponseValidator extends StatusResponseValidator
{
	/**
	 * @param consumerEndpointUri
	 * @param requestId
	 * @param trustChecker
	 */
	public LogoutResponseValidator(String consumerEndpointUri, String requestId, SamlTrustChecker trustChecker)
	{
		super(consumerEndpointUri, requestId, trustChecker);
	}

	public void validate(LogoutResponseDocument logoutResponseDoc) throws SAMLValidationException
	{
		StatusResponseType response = logoutResponseDoc.getLogoutResponse();
		super.validate(logoutResponseDoc, response);
		
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
