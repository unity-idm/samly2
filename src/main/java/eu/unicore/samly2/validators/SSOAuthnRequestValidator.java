/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.unicore.samly2.validators;

import eu.unicore.samly2.SAMLConstants;
import eu.unicore.samly2.exceptions.SAMLRequesterException;
import eu.unicore.samly2.exceptions.SAMLServerException;
import eu.unicore.samly2.trust.SamlTrustChecker;
import xmlbeans.org.oasis.saml2.assertion.NameIDType;
import xmlbeans.org.oasis.saml2.protocol.AuthnRequestDocument;
import xmlbeans.org.oasis.saml2.protocol.AuthnRequestType;

/**
 * Validates SAML Authentication Request, in accordance with the SSO profile. 
 * 
 * @author K. Benedyczak
 */
public class SSOAuthnRequestValidator extends AbstractRequestValidator
{
	public SSOAuthnRequestValidator(String consumerEndpointUri, SamlTrustChecker trustChecker,
			long requestValidity, ReplayAttackChecker replayChecker)
	{
		super(consumerEndpointUri, trustChecker, requestValidity, replayChecker);
	}

	public void validate(AuthnRequestDocument authenticationRequestDoc) throws SAMLServerException
	{
		AuthnRequestType authnRequest = authenticationRequestDoc.getAuthnRequest();
		super.validate(authenticationRequestDoc, authnRequest);
		
		validateIssuer(authnRequest);
	}
	
	protected void validateIssuer(AuthnRequestType authnRequest) throws SAMLServerException
	{
		NameIDType issuer = authnRequest.getIssuer();
		if (issuer == null)
			throw new SAMLRequesterException("Issuer of SAML request must be present in SSO AuthN");
		if (issuer.getFormat() != null && !issuer.getFormat().equals(SAMLConstants.NFORMAT_ENTITY))
			throw new SAMLRequesterException("Issuer of SAML request must be of Entity type in SSO AuthN. It is: " + issuer.getFormat());
		if (issuer.getStringValue() == null)
			throw new SAMLRequesterException("Issuer value of SAML request must be present in SSO AuthN");
	}
}
