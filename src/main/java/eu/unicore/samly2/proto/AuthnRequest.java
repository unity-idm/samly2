/*
 * Copyright (c) 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on Jul 16, 2008
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.samly2.proto;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import org.apache.xmlbeans.XmlException;
import org.w3c.dom.Document;

import eu.unicore.security.dsig.DSigException;

import xmlbeans.org.oasis.saml2.assertion.NameIDType;
import xmlbeans.org.oasis.saml2.protocol.AuthnRequestDocument;
import xmlbeans.org.oasis.saml2.protocol.AuthnRequestType;
import xmlbeans.org.oasis.saml2.protocol.NameIDPolicyType;

/**
 * SAML AuthenticationRequest creation utility.
 * @author golbi
 */
public class AuthnRequest extends AbstractRequest<AuthnRequestDocument, AuthnRequestType>
{
	public AuthnRequest(NameIDType issuer)
	{
		AuthnRequestDocument xbdoc = AuthnRequestDocument.Factory.newInstance();
		init(xbdoc, xbdoc.addNewAuthnRequest(), issuer);
	}

	public void setFormat(String format)
	{
		NameIDPolicyType policy = getXMLBean().addNewNameIDPolicy();
		policy.setFormat(format);
	}
	
	public void sign(PrivateKey pk, X509Certificate[] cert) 
		throws DSigException
	{
		Document doc = signInt(pk, cert);
		try
		{
			xmlDocuemnt = AuthnRequestDocument.Factory.parse(doc);
			xmlReq = xmlDocuemnt.getAuthnRequest();
		} catch (XmlException e)
		{
			throw new DSigException("Parsing signed document failed", e);
		}
	}
}