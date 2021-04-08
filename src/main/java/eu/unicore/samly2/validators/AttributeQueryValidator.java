/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.unicore.samly2.validators;

import java.util.HashSet;
import java.util.Set;

import eu.unicore.samly2.SAMLConstants;
import eu.unicore.samly2.exceptions.SAMLRequesterException;
import eu.unicore.samly2.exceptions.SAMLServerException;
import eu.unicore.samly2.messages.XMLExpandedMessage;
import eu.unicore.samly2.trust.SamlTrustChecker;

import xmlbeans.org.oasis.saml2.assertion.AttributeType;
import xmlbeans.org.oasis.saml2.protocol.AttributeQueryDocument;
import xmlbeans.org.oasis.saml2.protocol.AttributeQueryType;

/**
 * Validates SAML attribute assertion requests in accordance to SAML core and profile.
 * It is only verified if all requested attributes (if any) are specified only once.
 * 
 * @author K. Benedyczak
 */
public class AttributeQueryValidator extends AbstractSubjectQueryValidator
{
	public AttributeQueryValidator(String responderEndpointUri, SamlTrustChecker trustChecker,
			long requestValidity, ReplayAttackChecker replayChecker)
	{
		super(responderEndpointUri, trustChecker, requestValidity, replayChecker);
	}

	public void validate(AttributeQueryDocument wrappingDcoument) throws SAMLServerException
	{
		AttributeQueryType attributeQuery = wrappingDcoument.getAttributeQuery();
		XMLExpandedMessage verifiableMessage = new XMLExpandedMessage(wrappingDcoument, attributeQuery);
		super.validate(verifiableMessage, attributeQuery);

		AttributeType[] queriedAttrs = attributeQuery.getAttributeArray();
		Set<String> uniqueAttrs = new HashSet<String>();
		for (AttributeType qa: queriedAttrs)
			if (uniqueAttrs.contains(qa.getName()+"-||-"+qa.getNameFormat()))
				throw new SAMLRequesterException(
						SAMLConstants.SubStatus.STATUS2_INVALID_ATTR,
						"Invalid query: attribute must be specified only " +
						"once according to the SAML specification: " + qa.getName());
			else
				uniqueAttrs.add(qa.getName()+"-||-"+qa.getNameFormat());
	}
}
