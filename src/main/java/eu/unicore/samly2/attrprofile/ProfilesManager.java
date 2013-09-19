/*
 * Copyright (c) 2013 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.samly2.attrprofile;

import java.util.ArrayList;
import java.util.List;

import xmlbeans.org.oasis.saml2.assertion.AttributeType;


/**
 * Small class to manage attribute profiles
 * @author K. Benedyczak
 */
public class ProfilesManager
{
	private List<SAMLAttributeProfile> profiles;
	
	public ProfilesManager()
	{
		profiles = new ArrayList<SAMLAttributeProfile>(4);
		profiles.add(new SAMLDefaultAttributeProfile());
	}
	
	public void addProfile(SAMLAttributeProfile profile)
	{
		profiles.add(profile);
	}
	
	public SAMLAttributeProfile getBestProfile(AttributeType a)
	{
		int rank = -1;
		SAMLAttributeProfile selected = null;
		for (SAMLAttributeProfile profile: profiles)
		{
			int cur = profile.isSupported(a); 
			if (cur > rank)
			{
				rank = cur;
				selected = profile;
			}
		}
		return selected;
	}
	
	public SAMLAttributeProfile getBestProfile(ParsedAttribute a)
	{
		int rank = -1;
		SAMLAttributeProfile selected = null;
		for (SAMLAttributeProfile profile: profiles)
		{
			int cur = profile.isSupported(a); 
			if (cur > rank)
			{
				rank = cur;
				selected = profile;
			}
		}
		return selected;
	}

}
