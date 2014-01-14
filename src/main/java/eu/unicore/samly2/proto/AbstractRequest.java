/*
 * Copyright (c) 2007, 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on Sep 25, 2007
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.samly2.proto;

import java.util.Calendar;
import java.util.TimeZone;

import org.apache.xmlbeans.XmlObject;

import eu.unicore.samly2.SAMLConstants;

import xmlbeans.org.oasis.saml2.assertion.NameIDType;
import xmlbeans.org.oasis.saml2.protocol.ExtensionsType;
import xmlbeans.org.oasis.saml2.protocol.RequestAbstractType;

/**
 * Utility making creation of requests easier.
 * @author K. Benedyczak
 */
public abstract class AbstractRequest<T extends XmlObject, C extends RequestAbstractType> 
		extends AbstractSAMLMessage<T>
{
	protected C xmlReq;

	protected void init(T srcDoc, C src, NameIDType issuer)
	{
		xmlDocuemnt = srcDoc;
		xmlReq = src;
		xmlReq.setIssuer(issuer);
		xmlReq.setIssueInstant(Calendar.getInstance(TimeZone.getTimeZone("UTC")));
		xmlReq.setID(genID());
		xmlReq.setVersion(SAMLConstants.SAML2_VERSION);
	}
	
	public C getXMLBean()
	{
		return xmlReq;
	}
	
	public void setExtensions(XmlObject ext)
	{
		ExtensionsType exts = xmlReq.addNewExtensions();
		exts.set(ext);
	}
}
