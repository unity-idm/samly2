/*
 * Copyright (c) 2007, 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on Sep 25, 2007
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package pl.edu.icm.samly2.elements;

import javax.xml.namespace.QName;

import org.apache.xmlbeans.XmlCursor;
import org.apache.xmlbeans.XmlObject;
import org.apache.xmlbeans.XmlString;

import pl.edu.icm.samly2.SAMLConstants;

import xmlbeans.oasis.saml2.assertion.AttributeType;
import xmlbeans.pl.edu.icm.samlvo.attrext.ScopedStringAttributeValueType;

/**
 * @author K. Benedyczak
 */
public class SAMLAttribute
{
	private AttributeType xml;
	
	public SAMLAttribute(AttributeType xml)
	{
		this.xml = xml;
	}

	public SAMLAttribute(String name, String nameFormat)
	{
		this(name, nameFormat, SAMLConstants.XACMLDT_STRING);
	}
	
	public SAMLAttribute(String name, String nameFormat, String xacmlType)
	{
		xml = AttributeType.Factory.newInstance();
		xml.setName(name);
		xml.setNameFormat(nameFormat);
		XmlCursor cur = xml.newCursor();
		cur.toLastAttribute();
		cur.insertAttributeWithValue(SAMLConstants.XACMLDT, xacmlType);
		cur.dispose();
	}
	
	public SAMLAttribute(String name, String nameFormat, String xacmlType, 
			String friendlyName)
	{
		this(name, nameFormat, xacmlType);
		xml.setFriendlyName(friendlyName);
	}
	
	public void addStringAttributeValue(String value)
	{
		XmlObject o = xml.addNewAttributeValue();
		XmlString s = XmlString.Factory.newInstance();
		s.setStringValue(value);
		o.set(s);
	}

	public void addScopedStringAttributeValue(String value, String scope)
	{
		XmlObject o = xml.addNewAttributeValue();
		ScopedStringAttributeValueType valXml = 
			ScopedStringAttributeValueType.Factory.newInstance();
		valXml.setStringValue(value);
		valXml.setScope(scope);
		o.set(valXml);
	}
	
	public void addXMLAttribute(QName name, String value)
	{
		XmlCursor cur = xml.newCursor();
		cur.toLastAttribute();
		cur.insertAttributeWithValue(name, value);
		cur.dispose();
	}
	
	public AttributeType getXBean()
	{
		return xml;
	}
}
