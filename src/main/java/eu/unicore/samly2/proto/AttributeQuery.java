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

import eu.unicore.samly2.elements.SAMLAttribute;
import eu.unicore.security.dsig.DSigException;

import xmlbeans.org.oasis.saml2.assertion.NameIDType;
import xmlbeans.org.oasis.saml2.assertion.SubjectType;
import xmlbeans.org.oasis.saml2.protocol.AttributeQueryDocument;
import xmlbeans.org.oasis.saml2.protocol.AttributeQueryType;

/**
 * Allows for easy creation of Attribute queries.
 * @author K. Benedyczak
 */
public class AttributeQuery extends AbstractRequest<AttributeQueryDocument, AttributeQueryType>
{
	public AttributeQuery(NameIDType issuer, SubjectType subject)
	{
		AttributeQueryDocument xbdoc = AttributeQueryDocument.Factory.newInstance();
		init(xbdoc, xbdoc.addNewAttributeQuery(), issuer);
		getXMLBean().setSubject(subject);
	}
	
	public void setAttributes(SAMLAttribute attributes[])
	{
		for (int i=0; i<attributes.length; i++)
		{
			getXMLBean().insertNewAttribute(i);
			getXMLBean().setAttributeArray(i, attributes[i].getXBean());
		}
	}
	
	public void sign(PrivateKey pk, X509Certificate []cert) throws DSigException
	{
		Document doc = signInt(pk, cert);
		try
		{
			xmlDocuemnt = AttributeQueryDocument.Factory.parse(doc);
			xmlReq = xmlDocuemnt.getAttributeQuery();
		} catch (XmlException e)
		{
			throw new DSigException("Parsing signed document failed", e);
		}
	}
}



