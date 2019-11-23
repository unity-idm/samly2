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
import java.util.Calendar;
import java.util.Date;

import org.apache.xmlbeans.XmlException;
import org.w3c.dom.Document;

import eu.unicore.samly2.SAMLUtils;
import eu.unicore.security.dsig.DSigException;
import eu.unicore.security.enc.EncryptionUtil;
import xmlbeans.org.oasis.saml2.assertion.EncryptedElementType;
import xmlbeans.org.oasis.saml2.assertion.NameIDType;
import xmlbeans.org.oasis.saml2.protocol.LogoutRequestDocument;
import xmlbeans.org.oasis.saml2.protocol.LogoutRequestType;

/**
 * SAML LogoutRequest creation utility.
 * @author golbi
 */
public class LogoutRequest extends AbstractRequest<LogoutRequestDocument, LogoutRequestType>
{
	private final EncryptionUtil encryptEngine = new EncryptionUtil();
	
	public LogoutRequest(NameIDType issuer, NameIDType loggoutOutPrincipal)
	{
		LogoutRequestDocument xbdoc = LogoutRequestDocument.Factory.newInstance();
		init(xbdoc, xbdoc.addNewLogoutRequest(), issuer);
		xmlReq.setNameID(loggoutOutPrincipal);
	}

	public void setSessionIds(String... sessionIds)
	{
		xmlReq.setSessionIndexArray(sessionIds);
	}
	
	public void setNotAfter(Date when)
	{
		Calendar c = Calendar.getInstance();
		c.setTime(when);
		xmlReq.setNotOnOrAfter(c);
	}
	
	public void encryptSubject(PublicKey publicKey, int keySize) throws Exception
	{
		NameIDType nameID = xmlReq.getNameID();
		Document toEnc = SAMLUtils.getDOM(nameID);
		Document encrypted = encryptEngine.encrypt(toEnc, publicKey, keySize);
		EncryptedElementType contents = EncryptedElementType.Factory.parse(encrypted);
		xmlReq.setEncryptedID(contents);
		xmlReq.unsetNameID();
	}
	
	public void sign(PrivateKey pk, X509Certificate[] cert) 
		throws DSigException
	{
		Document doc = signInt(pk, cert);
		try
		{
			xmlDocuemnt = LogoutRequestDocument.Factory.parse(doc);
			xmlReq = xmlDocuemnt.getLogoutRequest();
		} catch (XmlException e)
		{
			throw new DSigException("Parsing signed document failed", e);
		}
	}
}