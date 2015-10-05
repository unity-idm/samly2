/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.unicore.samly2.trust;

import org.apache.xmlbeans.XmlObject;

import eu.unicore.samly2.exceptions.SAMLValidationException;
import xmlbeans.org.oasis.saml2.assertion.AssertionDocument;
import xmlbeans.org.oasis.saml2.protocol.RequestAbstractType;
import xmlbeans.org.oasis.saml2.protocol.StatusResponseType;

/**
 * Configures and performs checking whether consumer trusts the issuer of 
 * SAML assertion, request or response.
 * <p>
 * This implementation is always trusting everybody. Effectively it is useful on
 * server side, when everybody is allowed to send SAML requests or when authorization
 * is performed with other, non-SAML related methods. 
 * @author K. Benedyczak
 */
public class AcceptingSamlTrustChecker implements SamlTrustChecker
{
	@Override
	public void checkTrust(XmlObject requestDoc, RequestAbstractType request) throws SAMLValidationException
	{
	}

	@Override
	public void checkTrust(AssertionDocument assertionDoc,
			ResponseTrustCheckResult responseCheckResult)
			throws SAMLValidationException
	{
	}

	@Override
	public ResponseTrustCheckResult checkTrust(XmlObject responseDoc,
			StatusResponseType response) throws SAMLValidationException
	{
		return new ResponseTrustCheckResult(false);
	}
	
	@Override
	public void checkTrust(AssertionDocument assertionDoc) throws SAMLValidationException
	{
		checkTrust(assertionDoc, new ResponseTrustCheckResult(false));
	}
}
