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

import org.w3c.dom.Document;

import pl.edu.icm.samly2.SAMLConstants;
import pl.edu.icm.samly2.SAMLUtils;
import pl.edu.icm.samly2.dsig.DSigException;
import pl.edu.icm.samly2.elements.NameID;
import pl.edu.icm.samly2.exceptions.SAMLParseException;
import pl.edu.icm.samly2.exceptions.SAMLProtocolException;
import xmlbeans.org.oasis.saml2.protocol.StatusCodeType;
import xmlbeans.org.oasis.saml2.protocol.StatusResponseType;
import xmlbeans.org.oasis.saml2.protocol.StatusType;

/**
 * @author K. Benedyczak
 */
public abstract class AbstractStatusResponse extends AbstractSAMLMessage
{
	protected StatusResponseType xmlResp;
	
	protected AbstractStatusResponse()
	{
	}
	
	protected AbstractStatusResponse(StatusResponseType src) throws SAMLParseException
	{
		xmlResp = src;
	}

	protected void init(StatusResponseType src, NameID issuer, String inResponseTo)
	{
		xmlResp = src;
		xmlResp.setIssuer(issuer.getXBean());
		xmlResp.setIssueInstant(Calendar.getInstance());
		xmlResp.setID(genID());
		xmlResp.setVersion(SAMLConstants.SAML2_VERSION);
		if (inResponseTo != null)
			xmlResp.setInResponseTo(inResponseTo);
	}

	public void parse() throws SAMLParseException
	{
		if (xmlResp.getVersion() == null)
			throw new SAMLParseException("No SAML version is set");
		String ver = xmlResp.getVersion();
		if (!ver.equals(SAMLConstants.SAML2_VERSION))
			throw new SAMLParseException(
					"Only SAML 2.0 version is supported");
		
		if (xmlResp.getID() == null)
			throw new SAMLParseException("No ID is set");
		if (xmlResp.getIssueInstant() == null)
			throw new SAMLParseException("No IssueInstant is set");
		if (xmlResp.getStatus() == null)
			throw new SAMLParseException("No Status is set");
	}
	
	protected StatusType getOKStatus()
	{
		StatusType ok = StatusType.Factory.newInstance();
		StatusCodeType okCode = ok.addNewStatusCode();
		okCode.setValue(SAMLConstants.STATUS_OK);
		return ok;
	}

	protected StatusType getErrorStatus(SAMLProtocolException e)
	{
		StatusType error = StatusType.Factory.newInstance();
		StatusCodeType errorCode = error.addNewStatusCode();
		errorCode.setValue(e.getCode());
		if (e.getSubCode() != null)
			errorCode.addNewStatusCode().setValue(e.getSubCode());
		if (e.getMessage() != null)
			error.setStatusMessage(e.getMessage());
		return error;
	}

	public boolean isSigned()
	{
		if (xmlResp.getSignature() == null 
				|| xmlResp.getSignature().isNil())
			return false;
		else return true;
	}
	
	public Document getDOM() throws DSigException
	{
		return SAMLUtils.getDOM(getDoc());
	}
	
	public X509Certificate[] getIssuerFromSignature()
	{
		return SAMLUtils.getIssuerFromSignature(xmlResp.getSignature());
	}
	
	public boolean isStatusOK()
	{
		StatusType status = xmlResp.getStatus();
		if (status == null || status.getStatusCode() == null)
			return false;
		return status.getStatusCode().getValue().equals(SAMLConstants.STATUS_OK);
	}
	
	public String getErrorStatus()
	{
		StatusType status = xmlResp.getStatus();
		if (status == null || status.getStatusCode() == null)
			return null;
		return status.getStatusCode().getValue();
	}
	
	public String getSubErrorStatus()
	{
		StatusType status = xmlResp.getStatus();
		if (status == null || status.getStatusCode() == null ||
				status.getStatusCode().getStatusCode() == null)
			return null;
		return status.getStatusCode().getStatusCode().getValue();
	}
	
	public String getErrorMessage()
	{
		StatusType status = xmlResp.getStatus();
		if (status == null || status.getStatusCode() == null)
			return null;
		return status.getStatusMessage();
	}
}















