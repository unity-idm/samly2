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

import eu.unicore.security.dsig.DSigException;

import xmlbeans.org.oasis.saml2.assertion.NameIDType;
import xmlbeans.org.oasis.saml2.protocol.NameIDMappingRequestDocument;
import xmlbeans.org.oasis.saml2.protocol.NameIDMappingRequestType;
import xmlbeans.org.oasis.saml2.protocol.NameIDPolicyType;

/**
 * @author K. Benedyczak
 */
public class NameIDMappingRequest extends AbstractRequest<NameIDMappingRequestDocument, NameIDMappingRequestType>
{
	public NameIDMappingRequest(NameIDType issuer, NameIDType toMap, NameIDPolicyType policy)
	{
		NameIDMappingRequestDocument xbdoc = NameIDMappingRequestDocument.Factory.newInstance();
		init(xbdoc, xbdoc.addNewNameIDMappingRequest(), issuer);
		getXMLBean().setNameIDPolicy(policy);
		getXMLBean().setNameID(toMap);
	}
	
	@Override
	public void sign(PrivateKey pk, X509Certificate[] cert) throws DSigException
	{
		Document doc = signInt(pk, cert);
		try
		{
			xmlDocuemnt = NameIDMappingRequestDocument.Factory.parse(doc);
			xmlReq = xmlDocuemnt.getNameIDMappingRequest();
		} catch (XmlException e)
		{
			throw new DSigException("Parsing signed document failed", e);
		}
		
	}
}
