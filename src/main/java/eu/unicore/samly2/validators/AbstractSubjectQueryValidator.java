/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.unicore.samly2.validators;

import eu.unicore.samly2.exceptions.SAMLRequesterException;
import eu.unicore.samly2.exceptions.SAMLServerException;
import eu.unicore.samly2.messages.SAMLVerifiableElement;
import eu.unicore.samly2.trust.SamlTrustChecker;
import xmlbeans.org.oasis.saml2.assertion.SubjectType;
import xmlbeans.org.oasis.saml2.protocol.SubjectQueryAbstractType;

/**
 * Validates SAML subject requests - besides of {@link AbstractRequestValidator} it is 
 * checked if subject and issuer are set. Issuer is required to be present by SAML assertion 
 * query profile and subject requests are used with this profile.
 * 
 * @author K. Benedyczak
 */
public abstract class AbstractSubjectQueryValidator extends AbstractRequestValidator
{
	public AbstractSubjectQueryValidator(String responderEndpointUri,
			SamlTrustChecker trustChecker, long requestValidity,
			ReplayAttackChecker replayChecker)
	{
		super(responderEndpointUri, trustChecker, requestValidity, replayChecker);
	}

	public void validate(SAMLVerifiableElement verifiableRequestMessage, SubjectQueryAbstractType request) throws SAMLServerException
	{
		super.validate(verifiableRequestMessage, request);
		SubjectType subject = request.getSubject();
		if (subject == null || subject.isNil())
			throw new SAMLRequesterException("Subject can't be empty");
		
		if (subject.getNameID() == null || subject.getNameID().isNil())
			throw new SAMLRequesterException("Only subjects with nameID are supported.");
		
		if (request.getIssuer() == null || request.getIssuer().isNil() || 
				request.getIssuer().getStringValue() == null)
			throw new SAMLRequesterException("Issuer must be present");
	}
}
