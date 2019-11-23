/*
 * Copyright (c) 2019 Bixbit - Krzysztof Benedyczak. All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.samly2.slo;

import xmlbeans.org.oasis.saml2.assertion.NameIDType;

/**
 * Represents a SAML logout request which was parsed. The parsed class allows to read information from it,
 * but is fully immutable. 
 */
public class ParsedLogoutRequest
{
	private final NameIDType subject;
	private final NameIDType issuer;
	
	ParsedLogoutRequest(NameIDType subject, NameIDType issuer)
	{
		this.subject = subject;
		this.issuer = issuer;
	}

	public NameIDType getSubject()
	{
		return subject;
	}
	
	public NameIDType getIssuer()
	{
		return issuer;
	}
}
