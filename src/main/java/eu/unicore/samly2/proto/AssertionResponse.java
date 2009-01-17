/*
 * Copyright (c) 2007, 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on Sep 25, 2007
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.samly2.proto;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

import org.apache.xmlbeans.XmlException;
import org.w3c.dom.Document;

import eu.unicore.samly2.assertion.Assertion;
import eu.unicore.samly2.elements.NameID;
import eu.unicore.samly2.exceptions.SAMLParseException;
import eu.unicore.samly2.exceptions.SAMLProtocolException;
import eu.unicore.security.dsig.DSigException;

import xmlbeans.org.oasis.saml2.assertion.AssertionDocument;
import xmlbeans.org.oasis.saml2.assertion.AssertionType;
import xmlbeans.org.oasis.saml2.protocol.ResponseDocument;
import xmlbeans.org.oasis.saml2.protocol.ResponseType;

/**
 * @author K. Benedyczak
 */
public class AssertionResponse extends AbstractStatusResponse
{
	private ResponseType respXml;
	private ResponseDocument xbdoc;
	
	public AssertionResponse(ResponseDocument src) throws SAMLParseException
	{
		super(src.getResponse());
		xbdoc = src;
		respXml = src.getResponse();
	}
	
	public AssertionResponse(NameID issuer, String inResponseTo)
	{
		xbdoc = ResponseDocument.Factory.newInstance();
		respXml = xbdoc.addNewResponse();
		init(respXml, issuer, inResponseTo);
		respXml.setStatus(getOKStatus());
	}

	public AssertionResponse(NameID issuer, String inResponseTo, 
			SAMLProtocolException error)
	{
		xbdoc = ResponseDocument.Factory.newInstance();
		respXml = xbdoc.addNewResponse();
		init(respXml, issuer, inResponseTo);
		respXml.setStatus(getErrorStatus(error));
	}

	public ResponseDocument getDoc()
	{
		return xbdoc;
	}
	
	public void addAssertion(Assertion ass)
	{
		AssertionType at = respXml.addNewAssertion();
		at.set(ass.getXML().getAssertion());
	}
	
	public Assertion[] getAssertions() 
		throws SAMLParseException, XmlException, IOException
	{
		AssertionType[] xmlAs = respXml.getAssertionArray();
		if (xmlAs == null || xmlAs.length == 0)
			return new Assertion[0];
		Assertion []ret = new Assertion[xmlAs.length];
		for (int i=0; i<ret.length; i++)
		{
			AssertionDocument wrapper = AssertionDocument.Factory.newInstance();
			wrapper.setAssertion(xmlAs[i]);
			ret[i] = new Assertion(wrapper);
		}
		return ret;
	}
	                 
	
	@Override
	public boolean isCorrectlySigned(PublicKey key) throws DSigException
	{
		return isCorrectlySigned(key, (Document) xbdoc.getDomNode());
	}

	@Override
	public void sign(PrivateKey pk, X509Certificate[] cert) throws DSigException
	{
		Document doc = signInt(pk, cert);
		try
		{
			xbdoc = ResponseDocument.Factory.parse(doc);
			respXml = xbdoc.getResponse();
			respXml = xbdoc.getResponse();
		} catch (XmlException e)
		{
			throw new DSigException("Parsing signed document failed", e);
		}
	}

}
