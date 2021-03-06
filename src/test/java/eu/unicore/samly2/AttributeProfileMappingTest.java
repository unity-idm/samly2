/*
 * Copyright (c) 2015 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.samly2;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.File;

import org.apache.xmlbeans.XmlException;
import org.junit.Test;

import xmlbeans.org.oasis.saml2.assertion.AttributeType;
import xmlbeans.org.oasis.saml2.assertion.NameIDType;
import xmlbeans.org.oasis.saml2.protocol.ResponseDocument;
import eu.unicore.samly2.assertion.AttributeAssertionParser;
import eu.unicore.samly2.attrprofile.ParsedAttribute;
import eu.unicore.samly2.attrprofile.ProfilesManager;
import eu.unicore.samly2.attrprofile.SAMLAttributeProfile;
import eu.unicore.samly2.exceptions.SAMLValidationException;

public class AttributeProfileMappingTest
{
	public static final String NAMEID_ATTR = "<NameID "
			+ "Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent\" "
			+ "NameQualifier=\"https://idp\" "
			+ "SPNameQualifier=\"https://sp\">123asd</NameID>";
	
	@Test
	public void testNameIDMapping() throws XmlException, SAMLValidationException
	{
		ProfilesManager profilesManager = new ProfilesManager();
		
		AttributeType at = AttributeType.Factory.newInstance();
		NameIDType nameID = NameIDType.Factory.parse(NAMEID_ATTR);
		at.addNewAttributeValue().set(nameID);
		
		System.out.println(at.xmlText());
		
		SAMLAttributeProfile prof = profilesManager.getBestProfile(at);
		assertNotNull(prof);
		assertTrue(prof.isSupported(at) >= 0);
		ParsedAttribute mapped = prof.map(at);
		assertEquals(1, mapped.getStringValues().size());
		assertEquals("123asd", mapped.getStringValues().get(0));
	}
	
	@Test
	public void testPionierAssertion() throws Exception
	{
		ResponseDocument doc = ResponseDocument.Factory.parse(new File("src/test/resources/pionier id asercja.xml"));
		
		AttributeAssertionParser parser = new AttributeAssertionParser(doc.getResponse().getAssertionArray(0));
		
		System.out.println(parser.getAttributes());
	}
}
