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
import eu.unicore.samly2.exceptions.SAMLServerException;

import xmlbeans.org.oasis.saml2.assertion.NameIDType;
import xmlbeans.org.oasis.saml2.protocol.StatusCodeType;
import xmlbeans.org.oasis.saml2.protocol.StatusResponseType;
import xmlbeans.org.oasis.saml2.protocol.StatusType;

/**
 * @author K. Benedyczak
 */
public abstract class AbstractStatusResponse<T extends XmlObject, C extends StatusResponseType> extends AbstractSAMLMessage<T>
{
	protected C xmlResp;
	
	protected void init(T srcDoc, C src, NameIDType issuer, String inResponseTo)
	{
		xmlDocuemnt = srcDoc;
		xmlResp = src;
		xmlResp.setIssuer(issuer);
		xmlResp.setIssueInstant(Calendar.getInstance(TimeZone.getTimeZone("UTC")));
		xmlResp.setID(genID());
		xmlResp.setVersion(SAMLConstants.SAML2_VERSION);
		if (inResponseTo != null)
			xmlResp.setInResponseTo(inResponseTo);
	}

	public C getXMLBean()
	{
		return xmlResp;
	}
	
	public static StatusType createOKStatus()
	{
		StatusType ok = StatusType.Factory.newInstance();
		StatusCodeType okCode = ok.addNewStatusCode();
		okCode.setValue(SAMLConstants.Status.STATUS_OK.toString());
		return ok;
	}

	public static StatusType createErrorStatus(SAMLServerException e)
	{
		StatusType error = StatusType.Factory.newInstance();
		StatusCodeType errorCode = error.addNewStatusCode();
		errorCode.setValue(e.getSamlErrorId().toString());
		if (e.getSamlSubErrorId() != null)
			errorCode.addNewStatusCode().setValue(e.getSamlSubErrorId().toString());
		if (e.getMessage() != null)
			error.setStatusMessage(e.getMessage());
		return error;
	}
}















