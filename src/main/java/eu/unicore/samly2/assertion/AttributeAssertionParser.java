/*
 * Copyright (c) 2007, 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on May 6, 2007
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.samly2.assertion;

import java.util.ArrayList;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import xmlbeans.org.oasis.saml2.assertion.AssertionDocument;
import xmlbeans.org.oasis.saml2.assertion.AssertionType;
import xmlbeans.org.oasis.saml2.assertion.AttributeStatementType;
import xmlbeans.org.oasis.saml2.assertion.AttributeType;
import eu.unicore.samly2.attrprofile.ParsedAttribute;
import eu.unicore.samly2.attrprofile.ProfilesManager;
import eu.unicore.samly2.attrprofile.SAMLAttributeProfile;
import eu.unicore.samly2.exceptions.SAMLValidationException;


/**
 * SAML v2 attribute assertion parser. Helps to extract attributes.
 * 
 * @author K. Benedyczak
 */
public class AttributeAssertionParser extends AssertionParser
{
	private static final Logger log = LogManager.getLogger(AttributeAssertionParser.class);
	private static final long serialVersionUID=1L;
	private ProfilesManager profilesManager = new ProfilesManager();
	
	protected AttributeAssertionParser()
	{
	}
	
	public AttributeAssertionParser(AssertionDocument doc)
	{
		super(doc);
	}

	public AttributeAssertionParser(AssertionType assertion)
	{
		super(assertion);
	}
	
	public void addProfile(SAMLAttributeProfile profile)
	{
		profilesManager.addProfile(profile);
	}
	
	/**
	 * Returns the only attribute in the assertion. If the assertion contains more then one attribute 
	 * an exception is thrown. If there is no attribute then null is returned.
	 */
	public ParsedAttribute getAttribute() 
		throws SAMLValidationException
	{
		List<ParsedAttribute> list = getAttributesGeneric();
		if (list.size() == 0)
			return null;
		if (list.size() > 1)
			throw new SAMLValidationException("There are " + list.size() + " attributes, expected one.");
		return list.get(0);
	}

	public List<ParsedAttribute> getAttributes() throws SAMLValidationException
	{
		return getAttributesGeneric();
	}
	
	/**
	 * @return the first attribute with the given name found. There may be more then one attribute 
	 * with the same name, if there are more then one AttributeStatements. Null is returned when there is no 
	 * such attribute. 
	 */
	public ParsedAttribute getAttribute(String name) throws SAMLValidationException
	{
		for (AttributeStatementType as: assertionDoc.getAssertion().getAttributeStatementArray())
		{
			for (AttributeType xmlAttr: as.getAttributeArray())
			{
				if (name.equals(xmlAttr.getName()))
				{
					SAMLAttributeProfile profile = profilesManager.getBestProfile(xmlAttr);
					return profile.map(xmlAttr);
				}
			}
		}
		return null;
	}
	
	protected List<ParsedAttribute> getAttributesGeneric() throws SAMLValidationException
	{
		List<ParsedAttribute> ret = new ArrayList<ParsedAttribute>();
		for (AttributeStatementType as: assertionDoc.getAssertion().getAttributeStatementArray())
			parseAttributes(ret, as.getAttributeArray());
		return ret; 
	}
	
	protected void parseAttributes(List<ParsedAttribute> target, AttributeType[] xmlAttrs) throws SAMLValidationException
	{
		for (AttributeType xmlAttr: xmlAttrs)
		{
			SAMLAttributeProfile profile = profilesManager.getBestProfile(xmlAttr);
			if (profile != null)
				target.add(profile.map(xmlAttr));
			else
				log.info("The SAML attribute " + xmlAttr.getName() + 
						" will be ignored as there is no registered hadler for it.");
		}
	}
}
