/*
 * Copyright (c) 2011 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on 10-07-2011
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */
package eu.unicore.samly2.attrprofile;

import java.util.ArrayList;
import java.util.List;

import org.apache.xmlbeans.XmlAnySimpleType;
import org.apache.xmlbeans.XmlObject;
import org.apache.xmlbeans.XmlString;

import xmlbeans.org.oasis.saml2.assertion.AttributeType;
import xmlbeans.org.oasis.saml2.assertion.NameIDType;

/**
 * Default handler for simple attributes, intended to cover attributes
 * not handled by more specific profiles. Currently supports any attribute
 * with simple XSD type values or without values as well as the NameID attribute values used
 * in MACEDir profile.
 * 
 * @author K. Benedyczak
 */
public class SAMLDefaultAttributeProfile implements SAMLAttributeProfile
{
	@Override
	public int isSupported(AttributeType xmlAttr)
	{
		XmlObject []xmlVals = xmlAttr.getAttributeValueArray();

		if (xmlVals == null || xmlVals.length == 0)
			return DEFAULT_SUPPORT;
		
		if (xmlVals[0] instanceof XmlAnySimpleType)
			return DEFAULT_SUPPORT;
		
		if (xmlVals[0] instanceof NameIDType)
			return DEFAULT_SUPPORT;
		
		return -1;
	}
	
	@Override
	public int isSupported(ParsedAttribute attr)
	{
		return DEFAULT_SUPPORT;
	}
	
	@Override
	public ParsedAttribute map(AttributeType xmlAttr)
	{
		ParsedAttribute ret = new ParsedAttribute(xmlAttr.getName());
		String shortDesc = xmlAttr.getFriendlyName();
		ret.setDescription(shortDesc);
		XmlObject []xmlVals = xmlAttr.getAttributeValueArray();

		if (xmlVals == null || xmlVals.length == 0)
		{
			List<String> empty = new ArrayList<String>(0);
			ret.setValues(empty, empty);
			return ret;
		}
		
		List<String> values = new ArrayList<String>(xmlVals.length);
		for (int i=0; i<xmlVals.length; i++)
			values.add(mapAttrValue2APIAttr(xmlVals[i]));
		ret.setValues(values, values);
		return ret;
	}

	private String mapAttrValue2APIAttr(XmlObject value)
	{
		if (value instanceof XmlAnySimpleType)
		{
			return ((XmlAnySimpleType)value).getStringValue();
		} else 		if (value instanceof XmlAnySimpleType)
		{
			return ((NameIDType)value).getStringValue();
		} else
			throw new IllegalArgumentException("Unknown type of attribute " +
					"value received for DefaultSAMLProfile, " +
					"likely its a BUG, value " + value.xmlText());
	}

	@Override
	public AttributeType map(ParsedAttribute attr)
	{
		AttributeType ret = AttributeType.Factory.newInstance();
		ret.setName(attr.getName());
		if (attr.getDescription() != null)
			ret.setFriendlyName(attr.getDescription());
		List<String> values = attr.getStringValues();
		if (values.size() == 0)
			return ret;
		XmlString[] xmlVals = new XmlString[values.size()];
		int i=0;
		for (String value: values)
		{
			xmlVals[i] = XmlString.Factory.newInstance();
			xmlVals[i].setStringValue(value);
			i++;
		}
		ret.setAttributeValueArray(xmlVals);
		return ret;
	}
}
