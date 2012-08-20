/*
 * Copyright (c) 2009 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on 2010-02-10
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.security.dsig;

import java.security.cert.X509Certificate;

import xmlbeans.org.oasis.saml2.protocol.ResponseDocument;
import eu.unicore.samly2.assertion.Assertion;
import eu.unicore.samly2.exceptions.SAMLParseException;
import eu.unicore.samly2.proto.AssertionResponse;
import junit.framework.TestCase;

public class SAMLResponseParsingTest extends TestCase
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
		testResponseInternal("/signedResponse-xsw1.xml", 1, 0);
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
		testResponseInternal("/signedResponse-xsw2.xml", 1, 0);
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
		testResponseInternal("/signedResponse-xsw3.xml", 1, 0);
	}
	
	public void testResponse()
	{
		testResponseInternal("/signedResponse.xml", 1, 1);
	}
	
	private Assertion[] extractAssertions(String file)
	{
		ResponseDocument xmlRespDoc;
		try
		{
			xmlRespDoc = ResponseDocument.Factory.parse(
				getClass().getResourceAsStream(file));
		} catch (Exception e1)
		{
			fail("Error reading response file" + e1);
			return null;
		}
		
		AssertionResponse resp;
		try
		{
			resp = new AssertionResponse(xmlRespDoc);
			resp.parse();
		} catch (SAMLParseException e1)
		{
			fail("Error parsing response " + e1);
			return null;
		}
		
		if (!resp.isStatusOK())
			fail("Test response status was parsed in a wrong way - status shoulc be OK and isn't");

		try
		{
			return resp.getAssertions();
		} catch (Exception e)
		{
			e.printStackTrace();
			fail("Error getting assertions from request: " + e.toString());
			return null;
		}
	}
	
	private void testResponseInternal(String file, int expectedAssertions, int expectedValid)
	{
		Assertion[] assertions = extractAssertions(file); 
		int correct = 0;
		for (Assertion assertion: assertions)
		{
			X509Certificate[] issuersCC = assertion.getIssuerFromSignature();
			if (issuersCC == null || issuersCC.length == 0)
			{
				System.err.println("Couldn't get issuer cert from assertion");
				continue;
			}
			try
			{
				if (!assertion.isCorrectlySigned(issuersCC[0].getPublicKey())) {
					System.err.println("Response is incorrectly signed");
					continue;
				}
			} catch (DSigException e)
			{
				System.err.println("Problem when checking " +
						"response assertion signature with extracted " +
						"pub key: " + e + " sub cause: " + e.getCause());
				continue;
			}
			correct++;
		}
		
		if (assertions.length != expectedAssertions)
			fail("Should got " + expectedAssertions + " assertion(s) but got " + assertions.length);
		if (correct != expectedValid)
			fail("Should got " + expectedValid + " valid assertion(s) but got " + correct);
	}
}
