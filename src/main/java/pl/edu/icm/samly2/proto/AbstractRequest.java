/*
 * Copyright (c) 2007, 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on Sep 25, 2007
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package pl.edu.icm.samly2.proto;

import java.security.cert.X509Certificate;
import java.util.Calendar;

import org.apache.xmlbeans.XmlObject;
import org.w3c.dom.Document;

import pl.edu.icm.samly2.SAMLConstants;
import pl.edu.icm.samly2.SAMLUtils;
import pl.edu.icm.samly2.dsig.DSigException;
import pl.edu.icm.samly2.elements.NameID;
import pl.edu.icm.samly2.exceptions.SAMLProtocolException;
import pl.edu.icm.samly2.exceptions.SAMLRequestException;
import pl.edu.icm.samly2.exceptions.SAMLVersionException;

import xmlbeans.oasis.saml2.protocol.ExtensionsType;
import xmlbeans.oasis.saml2.protocol.RequestAbstractType;

/**
 * @author K. Benedyczak
 */
public abstract class AbstractRequest extends AbstractSAMLMessage
{
	protected RequestAbstractType xmlReq;

	protected AbstractRequest()
	{
	}
	
	protected AbstractRequest(RequestAbstractType src)
	{
		xmlReq = src;
	}

	protected void init(RequestAbstractType src, NameID issuer)
	{
		xmlReq = src;
		xmlReq.setIssuer(issuer.getXBean());
		xmlReq.setIssueInstant(Calendar.getInstance());
		xmlReq.setID(genID());
		xmlReq.setVersion(SAMLConstants.SAML2_VERSION);
	}
	

	public void parse() throws SAMLProtocolException
	{
		if (xmlReq.getVersion() == null)
			throw new SAMLVersionException(null, "No SAML version is set");
		String ver = xmlReq.getVersion();
		if (!ver.equals(SAMLConstants.SAML2_VERSION))
			throw new SAMLVersionException(null, 
				"Only SAML 2.0 version is supported");
		if (xmlReq.getID() == null)
			throw new SAMLRequestException(null, "No ID is set");
		if (xmlReq.getIssueInstant() == null)
			throw new SAMLRequestException(null, "No IssueInstant is set");
	}

	public String getID()
	{
		return xmlReq.getID();
	}
	
	public NameID getIssuer()
	{
		return new NameID(xmlReq.getIssuer());
	}
	
	public XmlObject getXMLBean()
	{
		return xmlReq;
	}
	
	public ExtensionsType getExtensions()
	{
		return xmlReq.getExtensions();
	}
	
	public void setExtensions(XmlObject ext)
	{
		ExtensionsType exts = xmlReq.addNewExtensions();
		exts.set(ext);
	}
	
	public Document getDOM() throws DSigException
	{
		return SAMLUtils.getDOM(getDoc()); 
	}
	
	public boolean isSigned()
	{
		if (xmlReq.getSignature() == null 
				|| xmlReq.getSignature().isNil())
			return false;
		else return true;
	}
	
	
	public X509Certificate[] getIssuerFromSignature()
	{
		return SAMLUtils.getIssuerFromSignature(xmlReq.getSignature());
	}
}
