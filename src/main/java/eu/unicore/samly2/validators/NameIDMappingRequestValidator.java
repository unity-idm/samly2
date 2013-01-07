/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.unicore.samly2.validators;

import eu.unicore.samly2.exceptions.SAMLRequesterException;
import eu.unicore.samly2.exceptions.SAMLServerException;
import eu.unicore.samly2.trust.SamlTrustChecker;
import xmlbeans.org.oasis.saml2.protocol.NameIDMappingRequestDocument;
import xmlbeans.org.oasis.saml2.protocol.NameIDMappingRequestType;
import xmlbeans.org.oasis.saml2.protocol.NameIDPolicyType;

/**
 * Validates SAML NameId Mapping Request using the SAML core and SAML NameId Mapping profile rules. 
 * 
 * @author K. Benedyczak
 */
public class NameIDMappingRequestValidator extends AbstractRequestValidator
{
	protected boolean requireSignature;
	
	public NameIDMappingRequestValidator(String consumerEndpointUri, SamlTrustChecker trustChecker,
			long requestValidity, ReplayAttackChecker replayChecker,
			boolean requireSignature)
	{
		super(consumerEndpointUri, trustChecker, requestValidity, replayChecker);
		this.requireSignature = requireSignature;
	}

	public void validate(NameIDMappingRequestDocument nameMappingRequestDoc) throws SAMLServerException
	{
		NameIDMappingRequestType request = nameMappingRequestDoc.getNameIDMappingRequest();
		super.validate(nameMappingRequestDoc, request);
		if (request.getIssuer() == null || request.getIssuer().isNil() || 
				request.getIssuer().getStringValue() == null)
			throw new SAMLRequesterException("Issuer must be present");
		
		NameIDPolicyType policy = request.getNameIDPolicy();
		if (policy == null || policy.isNil())
			throw new SAMLRequesterException("NameIDPolicy must be present");
		
		if ((request.getNameID() == null || request.getNameID().isNil()) && 
				(request.getBaseID() == null ||request.getBaseID().isNil()) && 
				(request.getEncryptedID() == null || request.getEncryptedID().isNil()))
			throw new SAMLRequesterException("No nameID to map is specified");
	}
}
