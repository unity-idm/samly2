/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.unicore.samly2.validators;

import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.List;

import eu.unicore.samly2.SAMLConstants;
import eu.unicore.samly2.SAMLUtils;
import eu.unicore.samly2.exceptions.SAMLRequesterException;
import eu.unicore.samly2.exceptions.SAMLValidationException;
import eu.unicore.samly2.messages.XMLExpandedMessage;
import eu.unicore.samly2.trust.ResponseTrustCheckResult;
import eu.unicore.samly2.trust.SamlTrustChecker;
import xmlbeans.org.oasis.saml2.assertion.AssertionDocument;
import xmlbeans.org.oasis.saml2.assertion.AssertionType;
import xmlbeans.org.oasis.saml2.assertion.NameIDType;
import xmlbeans.org.oasis.saml2.protocol.ResponseDocument;
import xmlbeans.org.oasis.saml2.protocol.ResponseType;

/**
 * Validates SAML Response, obtained after the SAML attribute assertion request. 
 * The response is checked in accordance to the SAML Assertion query profile.
 * Additionally it is verified if all assertions are attribute assertions and if are valid. 
 * 
 * @author K. Benedyczak
 */
public class AttributeAssertionResponseValidator extends StatusResponseValidator
{
	protected String consumerSamlName;
	protected long samlValidityGraceTime;
	protected NameIDType requestedSubject;
	protected PrivateKey decryptionKey;
	
	protected List<AssertionDocument> attributeAssertions;
	private final String consumerEndpointUri;
	private final String requestId;
	
	public AttributeAssertionResponseValidator(String consumerSamlName, String consumerEndpointUri, 
			String requestId, long samlValidityGraceTime, SamlTrustChecker trustChecker,
			NameIDType requestedSubject)
	{
		super(consumerEndpointUri, requestId, trustChecker);
		this.consumerSamlName = consumerSamlName;
		this.consumerEndpointUri = consumerEndpointUri;
		this.requestId = requestId;
		this.samlValidityGraceTime = samlValidityGraceTime;
		this.requestedSubject = requestedSubject;
	}

	public AttributeAssertionResponseValidator(String consumerSamlName, String consumerEndpointUri, 
			String requestId, long samlValidityGraceTime, SamlTrustChecker trustChecker,
			NameIDType requestedSubject, PrivateKey decryptionKey)
	{
		this(consumerSamlName, consumerEndpointUri, requestId, samlValidityGraceTime, 
				trustChecker, requestedSubject);
		this.decryptionKey = decryptionKey;
	}
	
	public void validate(ResponseDocument attributeResponseDoc) throws SAMLValidationException
	{
		attributeAssertions = new ArrayList<>();
		
		ResponseType response = attributeResponseDoc.getResponse();
		XMLExpandedMessage verifiableMessage = new XMLExpandedMessage(attributeResponseDoc, response);
		ResponseTrustCheckResult responseTrust = super.validate(verifiableMessage, response);
		
		NameIDType issuer = response.getIssuer();
		if (issuer == null || issuer.isNil() || issuer.getStringValue() == null)
			throw new SAMLRequesterException("Issuer must be present");
		if (issuer.getFormat() != null && !issuer.getFormat().equals(SAMLConstants.NFORMAT_ENTITY))
			throw new SAMLValidationException("Issuer of SAML response must be of Entity type in SSO AuthN. It is: " + issuer.getFormat());

		List<AssertionDocument> assertions;
		try
		{
			assertions = SAMLUtils.extractAllAssertions(response, decryptionKey);
		} catch (Exception e)
		{
			throw new SAMLValidationException("XML handling problem during retrieval of response assertions", e);
		}
		if (assertions == null)
			throw new SAMLValidationException("SAML response doesn't contain any assertion");
		AssertionValidator asValidator = new AssertionValidator(consumerSamlName, consumerEndpointUri, 
				requestId, samlValidityGraceTime, trustChecker, responseTrust);
		
		for (AssertionDocument assertionDoc: assertions)
		{
			AssertionType assertion = assertionDoc.getAssertion();
			if (assertion.sizeOfAttributeStatementArray() > 0)
				validateAssertion(assertionDoc, asValidator);
			else
				throw new SAMLValidationException("In response to attribute query got response with assertion without attribute statements");
		}
	}
	
	protected void validateAssertion(AssertionDocument assertionDoc, AssertionValidator asValidator) 
			throws SAMLValidationException
	{
		asValidator.validate(assertionDoc);
		AssertionType assertion = assertionDoc.getAssertion();
		NameIDType receivedSubject = assertion.getSubject().getNameID();

		if (!SAMLUtils.compareNameIDs(receivedSubject, requestedSubject))
			throw new SAMLValidationException("Received assertion for subject which was not requested: " + receivedSubject.xmlText() +
					"(requested was " + requestedSubject.xmlText() + ")");
		attributeAssertions.add(assertionDoc);
		
	}
	
	public List<AssertionDocument> getAttributeAssertions()
	{
		return attributeAssertions;
	}
}
