/*
 * Copyright (c) 2013 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.samly2;

import org.apache.xmlbeans.XmlAnySimpleType;
import org.apache.xmlbeans.XmlBase64Binary;
import org.apache.xmlbeans.XmlObject;

/**
 * This class will be replaced in close future with something more flexible, supporting 
 * various profiles.
 * 
 * For now it tries to extract a Java object from SAML attribute value.
 * 
 * @author K. Benedyczak
 */
public class AttributeValueExtractor
{
	/**
	 * @return either String or byte[]. String is returned for all simple types, except base64 binary which is
	 * converted to byte[].
	 */
	public static Object toJavaObject(XmlObject value)
	{
		if (value instanceof XmlBase64Binary)
		{
			return ((XmlBase64Binary)value).getByteArrayValue();
		}
		if (value instanceof XmlAnySimpleType)
		{
			return ((XmlAnySimpleType)value).getStringValue();
		}
		throw new IllegalArgumentException("Got unsupported attribute value XML object, the class is: " + 
				value.getClass().getName());
	}
}
