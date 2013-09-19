/*
 * Copyright (c) 2013 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.samly2.assertion;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import eu.unicore.samly2.attrprofile.ParsedAttribute;
import eu.unicore.samly2.attrprofile.ProfilesManager;
import eu.unicore.samly2.attrprofile.SAMLAttributeProfile;
import eu.unicore.samly2.exceptions.SAMLValidationException;

import xmlbeans.org.oasis.saml2.assertion.AttributeType;

/**
 * Allows for creating XML representation of SAML attributes from {@link ParsedAttribute}, using registered profiles. 
 * @author K. Benedyczak
 */
public class AttributeAssertionGenerator extends ProfilesManager
{
	public Collection<AttributeType> getAttributes(Collection<ParsedAttribute> src) throws SAMLValidationException
	{
		List<AttributeType> ret = new ArrayList<AttributeType>(src.size());
		for (ParsedAttribute attr: src)
		{
			SAMLAttributeProfile profile = getBestProfile(attr);
			ret.add(profile.map(attr));
		}
		return ret;
	}
	
	public AttributeType getAttribute(ParsedAttribute src) throws SAMLValidationException
	{
		SAMLAttributeProfile profile = getBestProfile(src);
		return profile.map(src);
	}
}
