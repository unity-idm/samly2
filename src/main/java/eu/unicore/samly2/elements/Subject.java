/*
 * Copyright (c) 2007, 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on Sep 25, 2007
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.samly2.elements;

import xmlbeans.org.oasis.saml2.assertion.NameIDType;
import xmlbeans.org.oasis.saml2.assertion.SubjectConfirmationType;
import xmlbeans.org.oasis.saml2.assertion.SubjectType;

/**
 * @author K. Benedyczak
 */
public class Subject
{
	private SubjectType xml;
	
	public Subject(String value, String format)
	{
		xml = SubjectType.Factory.newInstance();
		NameIDType name = xml.addNewNameID();
		name.setStringValue(value);
		name.setFormat(format);
	}
	
	public Subject(String value, String format, String nameQualifier, 
			String SPNameQualifier, String spProvidedId)
	{
		this(value, format);
		NameIDType name = xml.getNameID();
		name.setNameQualifier(nameQualifier);
		name.setSPNameQualifier(SPNameQualifier);
		name.setSPProvidedID(spProvidedId);
	}
	
	public void setSubjectConfirmation(SubjectConfirmationType conf[])
	{
		xml.setSubjectConfirmationArray(conf);
	}

	public SubjectType getXBean()
	{
		return xml;
	}
}
