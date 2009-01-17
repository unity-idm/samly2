/*
 * Copyright (c) 2007, 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on Sep 25, 2007
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package pl.edu.icm.samly2.proto;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

import org.apache.xmlbeans.XmlException;
import org.w3c.dom.Document;

import pl.edu.icm.samly2.dsig.DSigException;
import pl.edu.icm.samly2.elements.NameID;
import pl.edu.icm.samly2.elements.SAMLAttribute;
import pl.edu.icm.samly2.elements.Subject;
import pl.edu.icm.samly2.exceptions.SAMLProtocolException;
import xmlbeans.oasis.saml2.assertion.AttributeType;
import xmlbeans.oasis.saml2.protocol.AttributeQueryDocument;
import xmlbeans.oasis.saml2.protocol.AttributeQueryType;

/**
 * @author K. Benedyczak
 */
public class AttributeQuery extends AbstractSubjectQuery
{
	private AttributeQueryDocument xbdoc;
	private AttributeQueryType attrXml;
	
	public AttributeQuery(AttributeQueryDocument src) throws SAMLProtocolException
	{
		super(src.getAttributeQuery());
		xbdoc = src;
		attrXml = src.getAttributeQuery();
		parse();
	}
	
	public AttributeQuery(NameID issuer, Subject subject)
	{
		xbdoc = AttributeQueryDocument.Factory.newInstance();
		attrXml = xbdoc.addNewAttributeQuery();
		init(attrXml, issuer, subject);
	}
	
	public void setAttributes(SAMLAttribute attributes[])
	{
		for (int i=0; i<attributes.length; i++)
		{
			attrXml.insertNewAttribute(i);
			attrXml.setAttributeArray(i, attributes[i].getXBean());
		}
	}
	
	public AttributeType[] getAttributes()
	{
		return attrXml.getAttributeArray();
	}
	
	public AttributeQueryDocument getDoc()
	{
		return xbdoc;
	}
	
	public void sign(PrivateKey pk, X509Certificate []cert) throws DSigException
	{
		Document doc = signInt(pk, cert);
		try
		{
			xbdoc = AttributeQueryDocument.Factory.parse(doc);
			xmlReq = xbdoc.getAttributeQuery();
			attrXml = (AttributeQueryType)xmlReq;
		} catch (XmlException e)
		{
			throw new DSigException("Parsing signed document failed", e);
		}
	}
	
	public boolean isCorrectlySigned(PublicKey key) 
		throws DSigException
	{
		return isCorrectlySigned(key, (Document) xbdoc.getDomNode());
	}

}













