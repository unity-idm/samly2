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
import org.apache.xmlbeans.XmlObject;
import org.w3c.dom.Document;

import eu.unicore.samly2.exceptions.SAMLServerException;
import eu.unicore.security.dsig.DSigException;

import xmlbeans.org.oasis.saml2.assertion.NameIDType;
import xmlbeans.org.oasis.saml2.protocol.ExtensionsType;
import xmlbeans.org.oasis.saml2.protocol.NameIDMappingResponseDocument;
import xmlbeans.org.oasis.saml2.protocol.NameIDMappingResponseType;
import xmlbeans.org.oasis.saml2.protocol.StatusType;

/**
 * @author K. Benedyczak
 */
public class NameIDMappingResponse extends AbstractStatusResponse<NameIDMappingResponseDocument, NameIDMappingResponseType>
{
	public NameIDMappingResponse(NameIDType issuer, String inResponseTo, NameIDType mapped)
	{
		this(issuer, inResponseTo, mapped, createOKStatus());
	}

	public NameIDMappingResponse(NameIDType issuer, String inResponseTo, 
			SAMLServerException error)
	{
		this(issuer, inResponseTo, null, createErrorStatus(error));
	}

	public NameIDMappingResponse(NameIDType issuer, String inResponseTo, NameIDType mapped,
			StatusType status)
	{
		NameIDMappingResponseDocument xbdoc = NameIDMappingResponseDocument.Factory.newInstance();
		init(xbdoc, xbdoc.addNewNameIDMappingResponse(), issuer, inResponseTo);
		if (mapped != null)
			getXMLBean().setNameID(mapped);
		else
		{
			//ughhh -> what to do?? SAML requires nameID in response always,
			//even when there is an error!
			getXMLBean().addNewNameID().setNil();
		}
		getXMLBean().setStatus(status);
	}
	
	public void setExtensions(XmlObject val)
	{
		ExtensionsType exts = getXMLBean().getExtensions();
		if (exts == null)
			exts = getXMLBean().addNewExtensions();
		exts.set(val);
	}
	
	@Override
	public void sign(PrivateKey pk, X509Certificate[] cert) throws DSigException
	{
		Document doc = signInt(pk, cert);
		try
		{
			xmlDocuemnt = NameIDMappingResponseDocument.Factory.parse(doc);
			xmlResp = xmlDocuemnt.getNameIDMappingResponse();
			
		} catch (XmlException e)
		{
			throw new DSigException("Parsing signed document failed", e);
		}
	}
}
