/*
 * Copyright (c) 2011 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on 10-07-2011
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */
package eu.unicore.samly2.attrprofile;

import eu.unicore.samly2.exceptions.SAMLValidationException;

import xmlbeans.org.oasis.saml2.assertion.AttributeType;

/**
 * Implementations provide a support for mapping XML attributes to API {@link ParsedAttribute} class.
 *  
 * @author K. Benedyczak
 */
public interface SAMLAttributeProfile
{
	/**
	 * Attribute is supported by profile but only using a default policy,
	 * i.e. it is highly possible that that the attribute is defined in other profile.
	 */
	public int DEFAULT_SUPPORT = 0;

	/**
	 * The attribute is for sure from the profile.
	 */
	public int EXPLICIT_SUPPORT = 100;
	
	/**
	 * Checks if the XML attribute is supported.
	 * @param xmlAttr SAML attribute
	 * @return &gt;= 0 if the attribute is supported (higher number means higher 
	 * probability that the attribute is matching the profile), &lt;0 if not supported. 
	 */
	public int isSupported(AttributeType xmlAttr);

	/**
	 * Checks if the parsed attribute is supported.
	 * @param attr SAML attribute
	 * @return &gt;= 0 if the attribute is supported (higher number means higher 
	 * probability that the attribute is matching the profile), &lt;0 if not supported. 
	 */
	public int isSupported(ParsedAttribute attr);
	
	/**
	 * Performs the mapping.
	 *  
	 * @param xmlAttr SAML attribute to be mapped
	 * @return the mapped attribute
	 */
	public ParsedAttribute map(AttributeType xmlAttr) throws SAMLValidationException;
	
	/**
	 * Performs a mapping to the SAML attribute. Implementations should assume that name is set,
	 * and at least string or object values are set. If both are set then the profile is free to choose a preferred 
	 * version as input.
	 */
	public AttributeType map(ParsedAttribute attr) throws SAMLValidationException;
}
