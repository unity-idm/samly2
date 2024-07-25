/*
 * Copyright (c) 2013 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.samly2.attrprofile;

import java.io.Serializable;
import java.util.List;

import xmlbeans.org.oasis.saml2.assertion.AttributeType;

/**
 * Represents {@link AttributeType}, i.e. the XML SAML attribute in a converted form. 
 * Conversion is performed using SAML attribute profile handlers. It is needed as
 * the raw {@link AttributeType} is a generic type with unspecified XML contents and 
 * even retrieving string values is not very easy.
 * <p>
 * The attribute values can be always retrieved as Strings list, what is by far the most common
 * case. Additionally it is possible to get the values in a converted type - it can be used by some of the 
 * profile handlers to convert the values to different types. 
 * <p>
 * The description may be null. The other fields are always set by the profile handlers.
 * 
 * @author K. Benedyczak
 */
public class ParsedAttribute implements Serializable
{
	private static final long serialVersionUID = 1L;

	private String name;
	private String description;
	
	private List<String> stringValues;
	private List<?> objectValues;
	private Class<?> dataType;
	
	public ParsedAttribute(String name, String description, List<String> stringValues,
			List<Object> objectValues, Class<?> dataType)
	{
		this.name = name;
		this.description = description;
		this.stringValues = stringValues;
		this.objectValues = objectValues;
		this.dataType = dataType;
	}

	public ParsedAttribute(String name, String description, List<String> stringValues)
	{
		this.name = name;
		this.description = description;
		this.stringValues = stringValues;
		this.objectValues = stringValues;
		this.dataType = String.class;
	}
	
	public ParsedAttribute(String name)
	{
		this.name = name;
		this.dataType = String.class;
	}

	public String getName()
	{
		return name;
	}

	public void setName(String name)
	{
		this.name = name;
	}

	public String getDescription()
	{
		return description;
	}

	public void setDescription(String description)
	{
		this.description = description;
	}

	public List<String> getStringValues()
	{
		return stringValues;
	}

	public void setValues(List<String> stringValues, List<?> objectValues)
	{
		if (stringValues == null)
			throw new IllegalArgumentException("String representation of values must be always provided");
		this.stringValues = stringValues;
		this.objectValues = objectValues;
	}

	public List<?> getObjectValues()
	{
		return objectValues;
	}

	public Class<?> getDataType()
	{
		return dataType;
	}

	public void setDataType(Class<?> dataType)
	{
		this.dataType = dataType;
	}
}
