/*
 * Copyright (c) 2009 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on 2010-02-10
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.security.dsig;

import java.security.cert.X509Certificate;
import java.util.Collections;

import xmlbeans.org.oasis.saml2.assertion.AssertionDocument;
import xmlbeans.org.oasis.saml2.protocol.ResponseDocument;
import eu.unicore.samly2.SAMLUtils;
import eu.unicore.samly2.assertion.AssertionParser;
import eu.unicore.samly2.trust.StrictSamlTrustChecker;
import junit.framework.TestCase;

public class SAMLXSWAttackTest extends TestCase
{
	/**
	 * This one has the following structure:
	 * Faked Assertion with id of correct assertion A
	 * |->Signature of correct assertion A with its reference (ambiguous)
	 *    |->Correct assertion A with signature removed in <Object> element of the wrapping signature
	 * 
	 * Should fail as id is duplicated and therefore it is not possible to determine which 
	 * elements were really signed (and this is against spec).
	 */
	public void testWrongSignature1()
	{
		testResponseInternal("/signedResponse-xsw1.xml", false);
	}

	/**
	 * This one has the following structure:
	 * Faked Assertion with id 'evil'
	 * |->Signature of correct assertion A with its reference 
	 *    |->Correct assertion A with signature removed in <Object> element of the wrapping signature
	 *
	 * Should fail as the samly2 code should require that the root assertion element is signed.
	 */
	public void testWrongSignature2()
	{
		testResponseInternal("/signedResponse-xsw2.xml", false);
	}

	/**
	 * This one has the following structure:
	 * Faked Assertion with id 'evil'
	 * |->Signature of correct assertion A with its reference
	 *    |->Correct assertion A in <Object> element of the wrapping signature
	 *    
	 * Should fail as only one Signature element is allowed 
	 */
	public void testWrongSignature3()
	{
		testResponseInternal("/signedResponse-xsw3.xml", false);
	}
	
	public void testResponse()
	{
		testResponseInternal("/signedResponse.xml", true);
	}
	
	private void testResponseInternal(String file, boolean expectedValid)
	{
		ResponseDocument xmlRespDoc;
		try
		{
			xmlRespDoc = ResponseDocument.Factory.parse(
				getClass().getResourceAsStream(file));
		} catch (Exception e1)
		{
			fail("Error reading response file" + e1);
			return;
		}
		AssertionParser parser = new AssertionParser(xmlRespDoc.getResponse().getAssertionArray(0));
		X509Certificate[] issuersCC = parser.getIssuerFromSignature();
		StrictSamlTrustChecker trustChecker = new StrictSamlTrustChecker();
		trustChecker.addTrustedIssuer("http://localhost:9443", Collections.singletonList(issuersCC[0].getPublicKey()));
		
		
		try
		{
			AssertionDocument[] toCheck = SAMLUtils.getAssertions(xmlRespDoc.getResponse());
			for (AssertionDocument assertion: toCheck)
			{
				trustChecker.checkTrust(assertion);
			}
		} catch (Exception e)
		{
			if (!expectedValid)
			{
				System.out.println("Got expected trust validation problem: " + e);
				return;
			}
			e.printStackTrace();
			fail("Error verifying a correct request: " + e.toString());
		}
	}
}
