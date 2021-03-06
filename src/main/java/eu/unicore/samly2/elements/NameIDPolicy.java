/*
 * Copyright (c) 2007, 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on Sep 25, 2007
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.samly2.elements;

import xmlbeans.org.oasis.saml2.protocol.NameIDPolicyType;

/**
 * @author K. Benedyczak
 */
public class NameIDPolicy
{
	private NameIDPolicyType xml;
	
	public NameIDPolicy(String format)
	{
		xml = NameIDPolicyType.Factory.newInstance();
		xml.setFormat(format);
	}
	
	public NameIDPolicy(String format, String SPNameQualifier, boolean allowCreate)
	{
		this(format);
		xml.setSPNameQualifier(SPNameQualifier);
		xml.setAllowCreate(allowCreate);
	}
	
	public NameIDPolicyType getXBean()
	{
		return xml;
	}
}
