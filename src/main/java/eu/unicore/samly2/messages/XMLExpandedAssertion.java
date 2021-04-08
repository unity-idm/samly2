/*
 * Copyright (c) 2021 Bixbit - Krzysztof Benedyczak. All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.samly2.messages;

import eu.unicore.samly2.trust.SamlTrustChecker;
import xmlbeans.org.oasis.saml2.assertion.AssertionDocument;

/**
 * Assertion which can have its signature checked
 */
public class XMLExpandedAssertion extends XMLExpandedElement
{
	public XMLExpandedAssertion(AssertionDocument assertionDoc)
	{
		super(assertionDoc, assertionDoc.getAssertion().getSignature(), SamlTrustChecker.ASSERTION_ID_QNAME);
	}
}
