/*
 * Copyright (c) 2007, 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on Sep 25, 2007
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.samly2.proto;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import org.apache.xmlbeans.XmlException;
import org.w3c.dom.Document;

import eu.unicore.samly2.assertion.Assertion;
import eu.unicore.samly2.exceptions.SAMLServerException;
import eu.unicore.security.dsig.DSigException;

import xmlbeans.org.oasis.saml2.assertion.AssertionType;
import xmlbeans.org.oasis.saml2.assertion.NameIDType;
import xmlbeans.org.oasis.saml2.protocol.ResponseDocument;
import xmlbeans.org.oasis.saml2.protocol.ResponseType;
import xmlbeans.org.oasis.saml2.protocol.StatusType;

/**
 * @author K. Benedyczak
 */
public class AssertionResponse extends AbstractStatusResponse<ResponseDocument, ResponseType>
{
	public AssertionResponse(NameIDType issuer, String inResponseTo)
	{
		this(issuer, inResponseTo, createOKStatus());
	}

	public AssertionResponse(NameIDType issuer, String inResponseTo, 
			SAMLServerException error)
	{
		this(issuer, inResponseTo, createErrorStatus(error));
	}

	protected AssertionResponse(NameIDType issuer, String inResponseTo, StatusType status)
	{
		ResponseDocument xbdoc = ResponseDocument.Factory.newInstance();
		init(xbdoc, xbdoc.addNewResponse(), issuer, inResponseTo);
		getXMLBean().setStatus(status);
	}

	public void addAssertion(Assertion ass)
	{
		AssertionType at = getXMLBean().addNewAssertion();
		at.set(ass.getXMLBean());
	}
	                 
	@Override
	public void sign(PrivateKey pk, X509Certificate[] cert) throws DSigException
	{
		Document doc = signInt(pk, cert);
		try
		{
			xmlDocuemnt = ResponseDocument.Factory.parse(doc);
			xmlResp = xmlDocuemnt.getResponse();
		} catch (XmlException e)
		{
			throw new DSigException("Parsing signed document failed", e);
		}
	}

}
