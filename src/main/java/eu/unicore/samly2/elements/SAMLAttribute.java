/*
 * Copyright (c) 2007, 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on Sep 25, 2007
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.samly2.elements;

import javax.xml.namespace.QName;

import org.apache.xmlbeans.XmlCursor;
import org.apache.xmlbeans.XmlObject;
import org.apache.xmlbeans.XmlString;

import eu.unicore.samly2.SAMLConstants;

import xmlbeans.org.oasis.saml2.assertion.AttributeType;
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
		this(name, nameFormat, null, null, null);
	}
	
	public SAMLAttribute(String name, String nameFormat, String xacmlType, 
			String scopingType, String friendlyName)
	{
		xml = AttributeType.Factory.newInstance();
		xml.setName(name);
		xml.setNameFormat(nameFormat);
		if (friendlyName != null)
			xml.setFriendlyName(friendlyName);
		if (scopingType != null)
			setScopingType(scopingType);
		if (xacmlType != null)
			setXACMLDataType(xacmlType);
	}
	
	public void setFriendlyName(String friendlyName)
	{
		xml.setFriendlyName(friendlyName);
	}

	public String getFriendlyName()
	{
		return xml.getFriendlyName();
	}
	
	public void setScopingType(String type)
	{
		insertAttribute(SAMLConstants.SCOPE_TYPE_XMLATTRIBUTE.getLocalPart(),
				SAMLConstants.SCOPE_TYPE_XMLATTRIBUTE.getNamespaceURI(), type);
	}

	public String getScopingType()
	{
		return readAttribute(SAMLConstants.SCOPE_TYPE_XMLATTRIBUTE.getLocalPart(),
				SAMLConstants.SCOPE_TYPE_XMLATTRIBUTE.getNamespaceURI());
	}

	public void setAttributeWideScope(String scope)
	{
		insertAttribute(SAMLConstants.ATTRIBUTE_SCOPE_XMLATTRIBUTE.getLocalPart(),
				SAMLConstants.ATTRIBUTE_SCOPE_XMLATTRIBUTE.getNamespaceURI(), scope);
	}

	public String getAttributeWideScope()
	{
		return readAttribute(SAMLConstants.ATTRIBUTE_SCOPE_XMLATTRIBUTE.getLocalPart(),
				SAMLConstants.ATTRIBUTE_SCOPE_XMLATTRIBUTE.getNamespaceURI());
	}
	
	public void setXACMLDataType(String type)
	{
		insertAttribute(SAMLConstants.XACMLDT.getLocalPart(),
				SAMLConstants.XACMLDT.getNamespaceURI(), type);
	}

	public String getXACMLDataType()
	{
		return readAttribute(SAMLConstants.XACMLDT.getLocalPart(),
				SAMLConstants.XACMLDT.getNamespaceURI());
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
		if (value != null)
			valXml.setStringValue(value);
		else
			valXml.setNil();
		
		valXml.setScope(scope == null ? "/" : scope);
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
	
	private void insertAttribute(String name, String ns, String value)
	{
		XmlCursor cur = xml.newCursor();
		cur.toFirstChild();
		int i=0;
		String prefix = "urnx";
		while (cur.namespaceForPrefix(prefix + i) != null)
			i++;
		prefix = prefix + i;
		cur.toLastAttribute();
		cur.insertNamespace(prefix, ns);
		QName dtQN = new QName(ns, name, prefix);
		cur.insertAttributeWithValue(dtQN, value);
		cur.dispose();
	}
	
	private String readAttribute(String name, String ns)
	{
		XmlCursor cur = xml.newCursor();
		return cur.getAttributeText(new QName(ns, name));
	}

	@Override
	public int hashCode()
	{
		String nf1 = xml.getNameFormat();
		if (nf1 == null)
			nf1 = SAMLConstants.AFORMAT_UNSPEC;
		return (xml.getName()+"-----!!!----"+nf1).hashCode();
	}

	@Override
	public boolean equals(Object obj)
	{
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		SAMLAttribute other = (SAMLAttribute) obj;
		if (xml == null)
		{
			return other.xml == null;
		} else 
		{
			if (other.xml == null)
				return false;
			String nf1 = xml.getNameFormat();
			if (nf1 == null)
				nf1 = SAMLConstants.AFORMAT_UNSPEC;
			String nf2 = other.xml.getNameFormat();
			if (nf2 == null)
				nf2 = SAMLConstants.AFORMAT_UNSPEC;
			
			return other.xml.getName().equals(xml.getName()) && nf2.equals(nf1);
		}
	}
}
