/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.unicore.samly2.validators;

import java.util.ArrayList;
import java.util.List;

import eu.unicore.samly2.SAMLBindings;
import eu.unicore.samly2.SAMLConstants;
import eu.unicore.samly2.SAMLUtils;
import eu.unicore.samly2.exceptions.SAMLValidationException;
import eu.unicore.samly2.exceptions.SAMLValidationSoftException;
import eu.unicore.samly2.trust.SamlTrustChecker;
import xmlbeans.org.oasis.saml2.assertion.AssertionDocument;
import xmlbeans.org.oasis.saml2.assertion.AssertionType;
import xmlbeans.org.oasis.saml2.assertion.NameIDType;
import xmlbeans.org.oasis.saml2.protocol.ResponseDocument;
import xmlbeans.org.oasis.saml2.protocol.ResponseType;

/**
 * Validates SAML Response, obtained after the SAML Authentication request. 
 * The response is checked in accordance to the SSO profile. 
 * <p>
 * Note: it is not clearly defined in SSO profile whether InResponseTo must be defined 
 * and set for all assertions. We do require it for all assertions where subject confirmation 
 * is bearer. This rule always includes the authentication assertion, which must have the bearer confirmation.
 * 
 * @author K. Benedyczak
 */
public class SSOAuthnResponseValidator extends StatusResponseValidator
{
	protected ReplayAttackChecker replayChecker;
	protected String consumerSamlName;
	protected long samlValidityGraceTime;
	protected SAMLBindings binding;
	
	protected List<AssertionDocument> authNAssertions;
	protected List<AssertionDocument> otherAssertions;
	protected ErrorReasons reasons;
	
	/**
	 * @param consumerEndpointUri
	 * @param requestId
	 * @param trustChecker
	 */
	public SSOAuthnResponseValidator(String consumerSamlName, String consumerEndpointUri, 
			String requestId, long samlValidityGraceTime, SamlTrustChecker trustChecker, 
			ReplayAttackChecker replayChecker, SAMLBindings binding)
	{
		super(consumerEndpointUri, requestId, trustChecker);
		this.consumerSamlName = consumerSamlName;
		this.replayChecker = replayChecker;
		this.samlValidityGraceTime = samlValidityGraceTime;
		this.binding = binding;
	}

	public void validate(ResponseDocument authenticationResponseDoc) throws SAMLValidationException
	{
		authNAssertions = new ArrayList<AssertionDocument>();
		otherAssertions = new ArrayList<AssertionDocument>();
		reasons = new ErrorReasons();
		
		ResponseType response = authenticationResponseDoc.getResponse();
		super.validate(authenticationResponseDoc, response);
		
		NameIDType issuer = response.getIssuer();
		if (issuer != null)
		{
			if (issuer.getFormat() != null && !issuer.getFormat().equals(SAMLConstants.NFORMAT_ENTITY))
				throw new SAMLValidationException("Issuer of SAML response must be of Entity type in SSO AuthN. It is: " + issuer.getFormat());
		}

		AssertionDocument[] assertions;
		try
		{
			assertions = SAMLUtils.getAssertions(response);
		} catch (Exception e)
		{
			throw new SAMLValidationException("XML handling problem during retrieval of response assertions", e);
		}
		SSOAuthnAssertionValidator authnAsValidator = new SSOAuthnAssertionValidator(consumerSamlName, consumerEndpointUri, 
				requestId, samlValidityGraceTime, trustChecker, replayChecker, binding);
		AssertionValidator asValidator = new AssertionValidator(consumerSamlName, consumerEndpointUri, 
				null, samlValidityGraceTime, trustChecker);
		for (AssertionDocument assertionDoc: assertions)
		{
			AssertionType assertion = assertionDoc.getAssertion();
			if (assertion.sizeOfAuthnStatementArray() > 0)
				tryValidateAsAuthnAssertion(authnAsValidator, assertionDoc);
			else
				tryValidateAsGenericAssertion(asValidator, assertionDoc);

			//asIssuer is not null (checked for all assertions) and has proper format 
			//(checked for SSOAuth or manually above for other assertions)
			if (issuer == null)
				issuer = assertion.getIssuer();
			else if (!issuer.getStringValue().equals(assertion.getIssuer().getStringValue()))
				throw new SAMLValidationException("Inconsistent issuer in assertion: " + 
						assertion.getIssuer() + ", previously had: " + issuer);
		}
		if (authNAssertions.size() == 0)
		{
			if (reasons.getSize() > 0)
				throw new SAMLValidationException("Authentication assertion(s) was found, " +
						"but it was not correct wrt SSO profile: " + reasons);
			throw new SAMLValidationException("There was no authentication assertion found in the SAML response");
		}
	}
	
	public List<AssertionDocument> getAuthNAssertions()
	{
		return authNAssertions;
	}

	public List<AssertionDocument> getOtherAssertions()
	{
		return otherAssertions;
	}

	protected void tryValidateAsAuthnAssertion(SSOAuthnAssertionValidator authnAsValidator, 
			AssertionDocument assertionDoc) throws SAMLValidationException
	{
		try
		{
			authnAsValidator.validate(assertionDoc);
			authNAssertions.add(assertionDoc);
		} catch (SAMLValidationSoftException e)
		{
			reasons.addAssertionError(assertionDoc.getAssertion(), e.getMessage());
		}
	}

	protected void tryValidateAsGenericAssertion(AssertionValidator asValidator, 
			AssertionDocument assertionDoc) throws SAMLValidationException
	{
		asValidator.validate(assertionDoc);
		AssertionType assertion = assertionDoc.getAssertion();
		NameIDType asIssuer = assertion.getIssuer();
		if (asIssuer.getFormat() != null && !asIssuer.getFormat().equals(SAMLConstants.NFORMAT_ENTITY))
			throw new SAMLValidationException("Issuer of assertion must be of Entity type in SSO AuthN. It is: " + asIssuer.getFormat());
		if (binding == SAMLBindings.HTTP_POST && 
				(assertion.getSignature() == null || assertion.getSignature().isNil()))
			throw new SAMLValidationException("Assertion is not signed in the SSO authN used over HTTP POST, while should be.");

		otherAssertions.add(assertionDoc);
	}
}
