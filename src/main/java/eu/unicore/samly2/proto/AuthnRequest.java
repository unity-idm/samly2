/*
 * Copyright (c) 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on Jul 16, 2008
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.samly2.proto;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

import org.apache.xmlbeans.XmlException;
import org.w3c.dom.Document;

import eu.unicore.samly2.elements.NameID;
import eu.unicore.samly2.exceptions.SAMLProtocolException;
import eu.unicore.security.dsig.DSigException;

import xmlbeans.org.oasis.saml2.protocol.AuthnRequestDocument;
import xmlbeans.org.oasis.saml2.protocol.NameIDPolicyType;

/**
 * SAML AuthenticationRequest representation.
 * @author golbi
 */
public class AuthnRequest extends AbstractRequest
{
	private AuthnRequestDocument xbdoc;

	public AuthnRequest(AuthnRequestDocument src) throws SAMLProtocolException
	{
		super(src.getAuthnRequest());
		xbdoc = src;
		parse();
	}

	public AuthnRequest(NameID issuer)
	{
		xbdoc = AuthnRequestDocument.Factory.newInstance();
		init(xbdoc.addNewAuthnRequest(), issuer);
	}

	public void setFormat(String format)
	{
		NameIDPolicyType policy = xbdoc.getAuthnRequest().addNewNameIDPolicy();
		policy.setFormat(format);
	}
	
	public void setConsumerURL(String consumerURL)
	{
		xbdoc.getAuthnRequest().setAssertionConsumerServiceURL(consumerURL);
	}
	
	@Override
	public AuthnRequestDocument getDoc()
	{
		return xbdoc;
	}

	@Override
	public boolean isCorrectlySigned(PublicKey key) 
		throws DSigException
	{
		return isCorrectlySigned(key, (Document) xbdoc.getDomNode());
	}

	@Override
	public void sign(PrivateKey pk, X509Certificate[] cert) 
		throws DSigException
	{
		Document doc = signInt(pk, cert);
		try
		{
			xbdoc = AuthnRequestDocument.Factory.parse(doc);
			xmlReq = xbdoc.getAuthnRequest();
		} catch (XmlException e)
		{
			throw new DSigException("Parsing signed document failed", e);
		}
	}
	
}