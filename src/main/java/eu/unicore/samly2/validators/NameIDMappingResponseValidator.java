/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.unicore.samly2.validators;

import eu.unicore.samly2.SAMLConstants;
import eu.unicore.samly2.exceptions.SAMLValidationException;
import eu.unicore.samly2.trust.SamlTrustChecker;
import xmlbeans.org.oasis.saml2.assertion.NameIDType;
import xmlbeans.org.oasis.saml2.protocol.NameIDMappingResponseDocument;
import xmlbeans.org.oasis.saml2.protocol.NameIDMappingResponseType;

/**
 * Validates SAML Name ID Mapping Response using SAML core rules and the respective SAML profile.
 * 
 * @author K. Benedyczak
 */
public class NameIDMappingResponseValidator extends StatusResponseValidator
{
	/**
	 * @param consumerEndpointUri
	 * @param requestId
	 * @param trustChecker
	 */
	public NameIDMappingResponseValidator(String consumerEndpointUri, 
			String requestId, SamlTrustChecker trustChecker)
	{
		super(consumerEndpointUri, requestId, trustChecker);
	}

	public void validate(NameIDMappingResponseDocument mappingResponseDoc) throws SAMLValidationException
	{
		NameIDMappingResponseType respXml = mappingResponseDoc.getNameIDMappingResponse();
		super.validate(mappingResponseDoc, respXml);
		if (respXml.getNameID() == null || respXml.getEncryptedID() == null)
			throw new SAMLValidationException("No mapped name in response");
		
		NameIDType issuer = respXml.getIssuer();
		if (issuer == null || issuer.isNil())
			throw new SAMLValidationException("No issuer in response");
		if (issuer.getFormat() != null && !issuer.getFormat().equals(SAMLConstants.NFORMAT_ENTITY))
			throw new SAMLValidationException("Issuer must be of entity format, it is " + issuer.getFormat());
		if (issuer.getStringValue() == null)
			throw new SAMLValidationException("No issuer value in response");
	}
}
