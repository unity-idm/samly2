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

import xmlbeans.org.oasis.saml2.assertion.NameIDType;
import xmlbeans.org.oasis.saml2.protocol.LogoutResponseDocument;
import xmlbeans.org.oasis.saml2.protocol.StatusResponseType;
import xmlbeans.org.oasis.saml2.protocol.StatusType;
import eu.unicore.samly2.SAMLConstants;
import eu.unicore.samly2.exceptions.SAMLServerException;
import eu.unicore.security.dsig.DSigException;

/**
 * @author K. Benedyczak
 */
public class LogoutResponse extends AbstractStatusResponse<LogoutResponseDocument, StatusResponseType>
{
	public LogoutResponse(NameIDType issuer, String inResponseTo)
	{
		this(issuer, inResponseTo, createOKStatus());
	}

	public LogoutResponse(NameIDType issuer, String inResponseTo, 
			SAMLServerException error)
	{
		this(issuer, inResponseTo, createErrorStatus(error));
	}

	protected LogoutResponse(NameIDType issuer, String inResponseTo, StatusType status)
	{
		LogoutResponseDocument xbdoc = LogoutResponseDocument.Factory.newInstance();
		init(xbdoc, xbdoc.addNewLogoutResponse(), issuer, inResponseTo);
		getXMLBean().setStatus(status);
	}
	
	public void setPartialLogout()
	{
		xmlResp.getStatus().addNewStatusCode().setValue(
				SAMLConstants.SubStatus.STATUS2_PARTIAL_LOGOUT.toString());
	}

	@Override
	public void sign(PrivateKey pk, X509Certificate[] cert) throws DSigException
	{
		Document doc = signInt(pk, cert);
		try
		{
			xmlDocuemnt = LogoutResponseDocument.Factory.parse(doc);
			xmlResp = xmlDocuemnt.getLogoutResponse();
		} catch (XmlException e)
		{
			throw new DSigException("Parsing signed document failed", e);
		}
	}

}
