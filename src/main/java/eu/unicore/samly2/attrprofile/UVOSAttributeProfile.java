/*
 * Copyright (c) 2013 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.samly2.attrprofile;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

import org.apache.xmlbeans.XmlCursor;
import org.apache.xmlbeans.XmlObject;
import org.apache.xmlbeans.XmlString;

import xmlbeans.org.oasis.saml2.assertion.AttributeType;
import xmlbeans.pl.edu.icm.samlvo.attrext.ScopedStringAttributeValueType;
import eu.unicore.samly2.SAMLConstants;
import eu.unicore.samly2.exceptions.SAMLValidationException;

/**
 * Supports legacy UVOS scoped string attributes. This includes support of the XACML profile.
 * 
 * TODO: XACML profile support should be extracted to a separate profile, so it can be used independently 
 * or reused in other high-level profiles.
 * 
 * @author K. Benedyczak
 */
public class UVOSAttributeProfile implements SAMLAttributeProfile
{
	@Override
	public int isSupported(AttributeType xmlAttr)
	{
		XmlCursor cur = xmlAttr.newCursor();
		String scopingType = cur.getAttributeText(SAMLConstants.SCOPE_TYPE_XMLATTRIBUTE);
		String scope = cur.getAttributeText(SAMLConstants.ATTRIBUTE_SCOPE_XMLATTRIBUTE);
		cur.dispose();
		if (scopingType != null || scope != null)
			return EXPLICIT_SUPPORT;
		return -1;
	}

	@Override
	public ParsedAttribute map(AttributeType xmlAttr) throws SAMLValidationException
	{
		ParsedAttribute ret = new ParsedAttribute(xmlAttr.getName());
		ret.setDataType(ScopedStringValue.class);
		String shortDesc = xmlAttr.getFriendlyName();
		ret.setDescription(shortDesc);
		
		List<ScopedStringValue> values = new ArrayList<ScopedStringValue>();
		List<String> stringValues = new ArrayList<String>();
		ret.setValues(stringValues, values);
		XmlObject []xmlVals = xmlAttr.getAttributeValueArray();

		XmlCursor cur = xmlAttr.newCursor();
		String xacmlDT = cur.getAttributeText(SAMLConstants.XACMLDT);
		String scopingType = cur.getAttributeText(SAMLConstants.SCOPE_TYPE_XMLATTRIBUTE);
		String attributeScope = cur.getAttributeText(SAMLConstants.ATTRIBUTE_SCOPE_XMLATTRIBUTE);
		cur.dispose();
		
		if (xmlVals == null || xmlVals.length == 0)
		{
			values.add(new ScopedStringValue(attributeScope, xacmlDT, null));
			stringValues.add(null);
			return ret;
		}
		for (int i=0; i<xmlVals.length; i++)
		{
			ScopedStringValue tmp = mapAttrValue2APIValue(xmlVals[i], xacmlDT, scopingType);
			values.add(tmp);
			stringValues.add(tmp.getValue());
		}
		return ret;
	}

	private ScopedStringValue mapAttrValue2APIValue(XmlObject value, String xacmlType, String scopingType) 
			throws SAMLValidationException
	{
		String scope = null;
		String svalue = null;
		
		if (scopingType == null)
			scopingType = SAMLConstants.SCOPE_TYPE_NONE;
		
		if (value instanceof XmlString && 
				scopingType.equals(SAMLConstants.SCOPE_TYPE_NONE))
		{
			svalue = ((XmlString)value).getStringValue();
		} else if (value instanceof ScopedStringAttributeValueType && 
				scopingType.equals(SAMLConstants.SCOPE_TYPE_ATTRIBUTE))
		{
			ScopedStringAttributeValueType av = (ScopedStringAttributeValueType) value;
			scope = av.getScope();
			if (scope.equals("/"))
				scope = null;
			String v = av.getStringValue();
			if (!av.isNil())
				svalue = v;
		} else if (value instanceof XmlString && 
				scopingType.equals(SAMLConstants.SCOPE_TYPE_SIMPLE))
		{
			String content = ((XmlString)value).getStringValue();
			if (content == null || !content.contains("@/"))
				throw new SAMLValidationException(
					"Content of SimpleScopedString attribute value is invalid");
			int sep = content.lastIndexOf("@");
			if (sep + 2 < content.length())
				scope = content.substring(sep + 1);
			else
				scope = null;
			String v = content.substring(0, sep);
			if (!v.equals(""))
				svalue = v;
		} else
			throw new SAMLValidationException(
					"Unknown type of attribute " +
					"value received for UVOSSAMLProfile," +
					" likely it's a BUG, value " + value.xmlText());
		return new ScopedStringValue(scope, xacmlType, svalue);
	}
	
	@Override
	public AttributeType map(ParsedAttribute attr) throws SAMLValidationException
	{
		throw new RuntimeException("NOT implemented");
	}

	/**
	 * Used as high-level object value of the returned {@link ParsedAttribute}.
	 * Value, scope and xacmlDT.
	 * 
	 * @author K. Benedyczak
	 */
	public static class ScopedStringValue implements Serializable
	{
		private String scope;
		private String xacmlType;
		private String value;

		public ScopedStringValue(String scope, String xacmlType, String value)
		{
			this.scope = scope;
			this.xacmlType = xacmlType;
			this.value = value;
		}

		public String getScope()
		{
			return scope;
		}
		
		public String getValue()
		{
			return value;
		}

		public String getXacmlType()
		{
			return xacmlType;
		}
	}
}
