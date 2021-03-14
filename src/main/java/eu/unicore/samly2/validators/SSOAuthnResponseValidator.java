/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.unicore.samly2.validators;

import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.List;

import xmlbeans.org.oasis.saml2.assertion.AssertionDocument;
import xmlbeans.org.oasis.saml2.assertion.AssertionType;
import xmlbeans.org.oasis.saml2.assertion.NameIDType;
import xmlbeans.org.oasis.saml2.protocol.ResponseDocument;
import xmlbeans.org.oasis.saml2.protocol.ResponseType;
import eu.unicore.samly2.SAMLBindings;
import eu.unicore.samly2.SAMLConstants;
import eu.unicore.samly2.SAMLUtils;
import eu.unicore.samly2.exceptions.SAMLValidationException;
import eu.unicore.samly2.exceptions.SAMLValidationSoftException;
import eu.unicore.samly2.trust.CheckingMode;
import eu.unicore.samly2.trust.ResponseTrustCheckResult;
import eu.unicore.samly2.trust.SamlTrustChecker;

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
	protected PrivateKey decryptionKey;
	
	protected List<AssertionDocument> authNAssertions;
	protected List<AssertionDocument> attributeAssertions;
	protected List<AssertionDocument> otherAssertions;
	protected ErrorReasons reasons;
	private final String consumerEndpointUri;
	private final String requestId;
	
	public SSOAuthnResponseValidator(String consumerSamlName, String consumerEndpointUri, 
			String requestId, long samlValidityGraceTime, SamlTrustChecker trustChecker, 
			ReplayAttackChecker replayChecker, SAMLBindings binding)
	{
		super(consumerEndpointUri, requestId, trustChecker);
		this.consumerSamlName = consumerSamlName;
		this.consumerEndpointUri = consumerEndpointUri;
		this.requestId = requestId;
		this.replayChecker = replayChecker;
		this.samlValidityGraceTime = samlValidityGraceTime;
		this.binding = binding;
	}

	public SSOAuthnResponseValidator(String consumerSamlName, String consumerEndpointUri, 
			String requestId, long samlValidityGraceTime, SamlTrustChecker trustChecker, 
			ReplayAttackChecker replayChecker, SAMLBindings binding, PrivateKey decryptionKey)
	{
		this(consumerSamlName, consumerEndpointUri, requestId, samlValidityGraceTime, 
				trustChecker, replayChecker, binding);
		this.decryptionKey = decryptionKey;
	}

	
	public void validate(ResponseDocument authenticationResponseDoc) throws SAMLValidationException
	{
		authNAssertions = new ArrayList<AssertionDocument>();
		otherAssertions = new ArrayList<AssertionDocument>();
		attributeAssertions = new ArrayList<AssertionDocument>();
		reasons = new ErrorReasons();
		
		ResponseType response = authenticationResponseDoc.getResponse();
		ResponseTrustCheckResult responseTrust = super.validate(authenticationResponseDoc, response);
		
		NameIDType issuer = response.getIssuer();
		if (issuer != null)
		{
			if (issuer.getFormat() != null && !issuer.getFormat().equals(SAMLConstants.NFORMAT_ENTITY))
				throw new SAMLValidationException("Issuer of SAML response must be of Entity type in SSO AuthN. It is: " + issuer.getFormat());
		}
		
		List<AssertionDocument> assertions;
		try
		{
			assertions = SAMLUtils.extractAllAssertions(response, decryptionKey);
		} catch (Exception e)
		{
			throw new SAMLValidationException("XML handling problem during retrieval of response assertions", e);
		}
		

		SSOAuthnAssertionValidator authnAsValidator = new SSOAuthnAssertionValidator(consumerSamlName, 
				consumerEndpointUri, requestId, samlValidityGraceTime, trustChecker, replayChecker, 
				binding, responseTrust);
		AssertionValidator asValidator = new AssertionValidator(consumerSamlName, consumerEndpointUri, 
				null, samlValidityGraceTime, trustChecker, responseTrust);
		for (AssertionDocument assertionDoc: assertions)
		{
			AssertionType assertion = assertionDoc.getAssertion();
			if (assertion.sizeOfAuthnStatementArray() > 0)
				tryValidateAsAuthnAssertion(authnAsValidator, assertionDoc);
			if (assertion.sizeOfStatementArray() > 0 || assertion.sizeOfAttributeStatementArray() > 0 ||
					assertion.sizeOfAuthzDecisionStatementArray() > 0)
				tryValidateAsGenericAssertion(asValidator, assertionDoc, responseTrust);

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
	
	/**
	 * @return list of assertions with at least one authnStatement
	 */
	public List<AssertionDocument> getAuthNAssertions()
	{
		return authNAssertions;
	}

	/**
	 * @return list of assertions which has at least one statement other then authnStatement.
	 * Note that this may overlap with assertions returned by {@link #getAuthNAssertions()} in case
	 * when an assertion with statements of different types is received. 
	 */
	public List<AssertionDocument> getOtherAssertions()
	{
		return otherAssertions;
	}

	/**
	 * @return list of assertions which has at least one statement other then authnStatement.
	 * Note that this may overlap with assertions returned by {@link #getAuthNAssertions()} in case
	 * when an assertion with statements of different types is received. 
	 */
	public List<AssertionDocument> getAttributeAssertions()
	{
		return attributeAssertions;
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
			AssertionDocument assertionDoc, ResponseTrustCheckResult responseTrust) 
					throws SAMLValidationException
	{
		asValidator.validate(assertionDoc);
		AssertionType assertion = assertionDoc.getAssertion();
		NameIDType asIssuer = assertion.getIssuer();
		if (asIssuer.getFormat() != null && !asIssuer.getFormat().equals(SAMLConstants.NFORMAT_ENTITY))
			throw new SAMLValidationException("Issuer of assertion must be of Entity type in SSO AuthN. It is: " + asIssuer.getFormat());
		if (binding == SAMLBindings.HTTP_POST && 
				(assertion.getSignature() == null || assertion.getSignature().isNil()))
		{
			if (trustChecker.getCheckingMode() == CheckingMode.REQUIRE_SIGNED_ASSERTION)
			{
				throw new SAMLValidationException("Assertion is not signed in the SSO authN "
					+ "used over HTTP POST, while should be.");
			} else
			{
				if (!responseTrust.isTrustEstablished())
					throw new SAMLValidationException("Neither assertion nor "
							+ "response is signed, while at least one of "
							+ "them should be.");
			}
		}
		otherAssertions.add(assertionDoc);
		if (assertion.sizeOfAttributeStatementArray() > 0)
			attributeAssertions.add(assertionDoc);
	}
}
