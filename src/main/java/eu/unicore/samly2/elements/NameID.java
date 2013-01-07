/*
 * Copyright (c) 2007, 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on Sep 25, 2007
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.samly2.elements;

import xmlbeans.org.oasis.saml2.assertion.NameIDType;

/**
 * @author K. Benedyczak
 */
public class NameID
{
	private NameIDType xml;
	
	public NameID(String value, String format)
	{
		xml = NameIDType.Factory.newInstance();
		xml.setStringValue(value);
		xml.setFormat(format);
	}
	
	public NameID(String value, String format, String nameQualifier, 
			String SPNameQualifier, String spProvidedId)
	{
		this(value, format);
		xml.setNameQualifier(nameQualifier);
		xml.setSPNameQualifier(SPNameQualifier);
		xml.setSPProvidedID(spProvidedId);
	}
	
	public NameIDType getXBean()
	{
		return xml;
	}
}
