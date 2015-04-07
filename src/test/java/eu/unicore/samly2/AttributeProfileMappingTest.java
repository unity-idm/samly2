/*
 * Copyright (c) 2015 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.samly2;

import org.apache.xmlbeans.XmlException;

import xmlbeans.org.oasis.saml2.assertion.AttributeType;
import xmlbeans.org.oasis.saml2.assertion.NameIDType;
import eu.unicore.samly2.attrprofile.ParsedAttribute;
import eu.unicore.samly2.attrprofile.ProfilesManager;
import eu.unicore.samly2.attrprofile.SAMLAttributeProfile;
import eu.unicore.samly2.exceptions.SAMLValidationException;
import junit.framework.TestCase;

public class AttributeProfileMappingTest extends TestCase
{
	public static final String NAMEID_ATTR = "<NameID "
			+ "Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent\" "
			+ "NameQualifier=\"https://idp\" "
			+ "SPNameQualifier=\"https://sp\">123asd</NameID>";
	
	public void testNameIDMapping() throws XmlException, SAMLValidationException
	{
		ProfilesManager profilesManager = new ProfilesManager();
		
		AttributeType at = AttributeType.Factory.newInstance();
		NameIDType nameID = NameIDType.Factory.parse(NAMEID_ATTR);
		at.addNewAttributeValue().set(nameID);
		
		SAMLAttributeProfile prof = profilesManager.getBestProfile(at);
		assertNotNull(prof);
		assertTrue(prof.isSupported(at) >= 0);
		ParsedAttribute mapped = prof.map(at);
		assertEquals(1, mapped.getStringValues().size());
		assertEquals("123asd", mapped.getStringValues().get(0));
	}
}
