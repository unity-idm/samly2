/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.unicore.samly2.validators;

import java.util.Calendar;

import eu.unicore.samly2.SAMLBindings;
import eu.unicore.samly2.SAMLConstants;
import eu.unicore.samly2.exceptions.SAMLValidationException;
import eu.unicore.samly2.exceptions.SAMLValidationSoftException;
import eu.unicore.samly2.trust.SamlTrustChecker;
import xmlbeans.org.oasis.saml2.assertion.AssertionDocument;
import xmlbeans.org.oasis.saml2.assertion.AssertionType;
import xmlbeans.org.oasis.saml2.assertion.NameIDType;
import xmlbeans.org.oasis.saml2.assertion.SubjectConfirmationDataType;
import xmlbeans.org.oasis.saml2.assertion.SubjectConfirmationType;
import xmlbeans.org.oasis.saml2.assertion.SubjectType;

/**
 * Implements validation of the authentication assertions, according to the
 * SSO SAML authentication profile.
 * @author K. Benedyczak
 */
public class SSOAuthnAssertionValidator extends AssertionValidator
{
	protected ReplayAttackChecker replayChecker;
	protected SAMLBindings binding;
	
	/**
	 * @param consumerSamlName
	 * @param consumerEndpointUri
	 * @param requestId
	 * @param samlValidityGraceTime
	 * @param trustChecker
	 */
	public SSOAuthnAssertionValidator(String consumerSamlName, String consumerEndpointUri,
			String requestId, long samlValidityGraceTime, SamlTrustChecker trustChecker,
			ReplayAttackChecker replayChecker, SAMLBindings binding)
	{
		super(consumerSamlName, consumerEndpointUri, requestId, samlValidityGraceTime, trustChecker);
		this.replayChecker = replayChecker;
		this.binding = binding;
	}

	@Override
	public void validate(AssertionDocument assertionDoc) throws SAMLValidationException
	{
		super.validate(assertionDoc);
		AssertionType assertionXml = assertionDoc.getAssertion();
		
		//0 - all statements of a single type
		checkStatements(assertionXml);
		
		//1 - issuer format unspec or entity
		NameIDType issuer = assertionXml.getIssuer();
		if (issuer.getFormat() != null && !SAMLConstants.NFORMAT_ENTITY.equals(
				issuer.getFormat()))
			throw new SAMLValidationException("SAML SSO authentication profile " +
					"requires issuer to be of entity type. Was: " + issuer.getFormat());
		
		//2 - has authN statements
		if (assertionXml.getAuthnStatementArray() == null ||
				assertionXml.getAuthnStatementArray().length == 0)
			throw new SAMLValidationException("Not an authentication assertion - no authN satements");
		
		//3 - bearer confirmation with Recipient, NotOnOrAfter set and without NotBefore with correct InResponseTo
		Calendar notAfter = checkAuthNSubject(assertionXml.getSubject());
		
		//4 - audience restriction present
		if (assertionXml.getConditions() == null || 
				assertionXml.getConditions().getAudienceRestrictionArray() == null ||
				assertionXml.getConditions().getAudienceRestrictionArray().length == 0)
			throw new SAMLValidationSoftException("SAML SSO authentication profile " +
					"requires that audience restriction must be set and it wasn't.");
			
		if (binding == SAMLBindings.HTTP_POST)
		{
			//5 - replay attack check
			replayChecker.checkAndStore(assertionXml.getID(), notAfter);
		
			//6 - must be signed
			if (assertionXml.getSignature() == null || assertionXml.getSignature().isNil())
				throw new SAMLValidationException("Assertion is not signed in the SSO authN used over HTTP POST, while should be.");
				
		}
	}
	
	protected Calendar checkAuthNSubject(SubjectType subject) throws SAMLValidationSoftException
	{
		SubjectConfirmationType[] confirmations = subject.getSubjectConfirmationArray();
		if (confirmations == null || confirmations.length == 0)
			throw new SAMLValidationSoftException("Authentication assertion subject confirmation is not set");
		for (SubjectConfirmationType confirmation: confirmations)
		{
			SubjectConfirmationDataType confData = confirmation.getSubjectConfirmationData();
			if (!SAMLConstants.CONFIRMATION_BEARER.equals(confirmation.getMethod()))
				continue;
			if (confData == null || confData.isNil())
				throw new SAMLValidationSoftException("In authentication assertion the bearer subject confirmation must have confirmation data set");
			
			if (confData.getRecipient() == null)
				throw new SAMLValidationSoftException("Authentication assertion confirmation receipent URL must be set");
			
			if (confData.getNotOnOrAfter() == null)
				throw new SAMLValidationSoftException("Bearer subject confirmation must have notOnOrAfter defined");

			if (confData.getNotBefore() != null)
				throw new SAMLValidationSoftException("Bearer subject confirmation must not have notBefore defined");

			if (requestId == null && confData.isSetInResponseTo())
				throw new SAMLValidationSoftException("InResponseTo present, while it was expected to have an unsolicited response");
			return confData.getNotOnOrAfter();
		}
		
		throw new SAMLValidationSoftException("Authentication assertion subject doesn't posses any bearer type subject confirmation");
	}

}
