/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.unicore.samly2.validators;

import org.apache.xmlbeans.XmlObject;

import eu.unicore.samly2.exceptions.SAMLValidationException;
import eu.unicore.samly2.trust.ResponseTrustCheckResult;
import eu.unicore.samly2.trust.SamlTrustChecker;
import xmlbeans.org.oasis.saml2.protocol.StatusResponseType;

/**
 * As {@link CommonResponseValidator} but adds trust checking with {@link SamlTrustChecker}
 */
public class StatusResponseValidator
{
	private final CommonResponseValidator commonValidator;
	protected SamlTrustChecker trustChecker;

	public StatusResponseValidator(String consumerEndpointUri, String requestId,
			SamlTrustChecker trustChecker)
	{
		this.commonValidator = new CommonResponseValidator(consumerEndpointUri, requestId);
		if (trustChecker == null)
			throw new IllegalArgumentException("The SAMLTrustChecker can not be null");
		this.trustChecker = trustChecker;
	}
	
	public ResponseTrustCheckResult validate(XmlObject wrappingDcoument, StatusResponseType responseXml) 
			throws SAMLValidationException
	{
		commonValidator.validate(wrappingDcoument, responseXml);
		return trustChecker.checkTrust(wrappingDcoument, responseXml);
	}
}
