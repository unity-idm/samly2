/*
 * Copyright (c) 2007, 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on Sep 25, 2007
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.samly2.proto;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

import org.apache.xmlbeans.XmlException;
import org.w3c.dom.Document;

import eu.unicore.samly2.SAMLConstants;
import eu.unicore.samly2.elements.NameID;
import eu.unicore.samly2.elements.NameIDPolicy;
import eu.unicore.samly2.exceptions.SAMLProtocolException;
import eu.unicore.samly2.exceptions.SAMLRequestException;
import eu.unicore.security.dsig.DSigException;

import xmlbeans.org.oasis.saml2.assertion.NameIDType;
import xmlbeans.org.oasis.saml2.protocol.NameIDMappingRequestDocument;
import xmlbeans.org.oasis.saml2.protocol.NameIDMappingRequestType;
import xmlbeans.org.oasis.saml2.protocol.NameIDPolicyType;

/**
 * @author K. Benedyczak
 */
public class NameIDMappingRequest extends AbstractRequest
{
	private NameIDMappingRequestDocument xbdoc;
	private NameIDMappingRequestType mapXml;
	
	public NameIDMappingRequest(NameIDMappingRequestDocument src) 
		throws SAMLProtocolException
	{
		super(src.getNameIDMappingRequest());
		xbdoc = src;
		mapXml = xbdoc.getNameIDMappingRequest();
		parse();
	}
	
	public NameIDMappingRequest(NameID issuer, NameID toMap, NameIDPolicy policy)
	{
		xbdoc = NameIDMappingRequestDocument.Factory.newInstance();
		mapXml = xbdoc.addNewNameIDMappingRequest();
		init(mapXml, issuer);
		mapXml.setNameIDPolicy(policy.getXBean());
		mapXml.setNameID(toMap.getXBean());
	}
	
	public void parse() throws SAMLProtocolException
	{
		super.parse();
		NameIDPolicyType policy = mapXml.getNameIDPolicy();
		if (policy == null)
			throw new SAMLRequestException(null, "NameIDPolicy can't be null");
		if (policy.getSPNameQualifier() != null)
			throw new SAMLRequestException(
				SAMLConstants.STATUS2_INVALID_NAMEID_POLICY, 
				"Specified SPNameQualifier is unknown");
		String requestedFormat = policy.getFormat();
		if (requestedFormat == null)
			requestedFormat = SAMLConstants.NFORMAT_UNSPEC;
		if (requestedFormat.equals(SAMLConstants.NFORMAT_ENC))
			throw new SAMLRequestException(
				SAMLConstants.STATUS2_INVALID_NAMEID_POLICY, 
				"Encryption of names is unsupported.");
			
		NameIDType originalName = mapXml.getNameID();
		if (originalName == null)
		{
			if (mapXml.getBaseID() != null || mapXml.getEncryptedID() != null)
				throw new SAMLRequestException(
					SAMLConstants.STATUS2_UNKNOWN_PRINCIPIAL,
					"Only NameID element is supported as a way " +
					"to specify name to be mapped");
			else
				throw new SAMLRequestException(null, 
					"No nameID to map is specified");
		}
	}

	public NameIDPolicy getPolicy()
	{
		return new NameIDPolicy(mapXml.getNameIDPolicy());
	}
	
	public NameID getNameToMap()
	{
		return new NameID(mapXml.getNameID());
	}
	
	@Override
	public boolean isCorrectlySigned(PublicKey key) throws DSigException
	{
		return isCorrectlySigned(key, (Document) xbdoc.getDomNode());
	}

	@Override
	public void sign(PrivateKey pk, X509Certificate[] cert) throws DSigException
	{
		Document doc = signInt(pk, cert);
		try
		{
			xbdoc = NameIDMappingRequestDocument.Factory.parse(doc);
			xmlReq = xbdoc.getNameIDMappingRequest();
			mapXml = xbdoc.getNameIDMappingRequest();
		} catch (XmlException e)
		{
			throw new DSigException("Parsing signed document failed", e);
		}
		
	}
	
	public NameIDMappingRequestDocument getDoc()
	{
		return xbdoc;
	}
}
