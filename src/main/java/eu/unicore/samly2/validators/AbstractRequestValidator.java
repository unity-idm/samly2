/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.unicore.samly2.validators;

import eu.unicore.samly2.SAMLConstants;
import eu.unicore.samly2.exceptions.SAMLRequesterException;
import eu.unicore.samly2.exceptions.SAMLServerException;
import eu.unicore.samly2.exceptions.SAMLValidationException;
import eu.unicore.samly2.messages.SAMLVerifiableElement;
import eu.unicore.samly2.trust.SamlTrustChecker;
import xmlbeans.org.oasis.saml2.protocol.RequestAbstractType;

/**
 * Validates SAML RequestAbstractType, which is the base of all SAML requests. 
 * The SAML 2.0 core specification rules are checked. This class
 * is SAML profile/binding independent.
 * <p>
 * Besides of SAML spec rules this class implements also additional checks:
 * <ul>
 * <li> the request's issueInstant attribute is checked to fall in an allowed time frame, 
 * to detect outdated requests,
 * <li> replay checking is performed.
 * </ul> 
 * 
 * @author K. Benedyczak
 */
public class AbstractRequestValidator
{
	private final CommonRequestValidation commonRequestValidation;
	private SamlTrustChecker trustChecker;

	public AbstractRequestValidator(String responderEndpointUri, SamlTrustChecker trustChecker,
			long requestValidity, ReplayAttackChecker replayChecker)
	{
		this.commonRequestValidation = new CommonRequestValidation(responderEndpointUri, 
				requestValidity, replayChecker);
		this.trustChecker = trustChecker;
	}
	
	public void validate(SAMLVerifiableElement verifiableRequestMessage, RequestAbstractType request) throws SAMLServerException
	{
		commonRequestValidation.validateBasicElements(request);
		try
		{
			trustChecker.checkTrust(verifiableRequestMessage, request);
		} catch (SAMLValidationException e)
		{
			throw new SAMLRequesterException(SAMLConstants.SubStatus.STATUS2_REQUEST_DENIED,
					e.getMessage(), e);
		}
		commonRequestValidation.validateReply(request);
	}
}
