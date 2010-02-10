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
	public void testResponse()
	{
		ResponseDocument xmlRespDoc;
		try
		{
			xmlRespDoc = ResponseDocument.Factory.parse(
				getClass().getResourceAsStream("/signedResponse.xml"));
		} catch (Exception e1)
		{
			fail("Error reading response file" + e1);
			return;
		}
		
		AssertionResponse resp;
		try
		{
			resp = new AssertionResponse(xmlRespDoc);
			resp.parse();
		} catch (SAMLParseException e1)
		{
			fail("Error parsing response " + e1);
			return;
		}
		
		if (!resp.isStatusOK())
			fail("Test response status was parsed in a wrong way - status shoulc be OK and isn't");

		Assertion[] assertions;
		try
		{
			assertions = resp.getAssertions();
		} catch (Exception e)
		{
			fail("Error getting assertions from request: " + e.toString());
			return;
		}
		
		if (assertions.length == 0 || assertions.length > 1)
			fail("Should get one assertion but got " + assertions.length);
		Assertion assertion = assertions[0];

		X509Certificate[] issuersCC = assertion.getIssuerFromSignature();
		if (issuersCC == null || issuersCC.length == 0)
			fail("Couldn't get issuer cert from assertion");
		try
		{
			if (!assertion.isCorrectlySigned(issuersCC[0].getPublicKey()))
				fail("Response is incorrectly signed");
		} catch (DSigException e)
		{
			fail("Problem when checking " +
				"response assertion signature with extracted " +
				"pub key: " + e);
		}
	}
}
