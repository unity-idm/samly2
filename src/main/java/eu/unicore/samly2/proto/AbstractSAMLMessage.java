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

import org.apache.xmlbeans.XmlObject;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import eu.unicore.samly2.SAMLUtils;
import eu.unicore.samly2.trust.SamlTrustChecker;
import eu.unicore.security.dsig.DSigException;
import eu.unicore.security.dsig.DigSignatureUtil;


/**
 * Base class for creating SAML requests and responses.
 * @author K. Benedyczak
 */
public abstract class AbstractSAMLMessage<T extends XmlObject>
{
	private static String ID_PREFIX = "SAMLY2lib_msg_";
	
	public abstract void sign(PrivateKey pk, X509Certificate []cert) 
		throws DSigException;
	
	protected T xmlDocuemnt;
	
	
	public T getXMLBeanDoc()
	{
		return xmlDocuemnt;
	}

	public Document getDOM() throws DSigException
	{
		return SAMLUtils.getDOM(getXMLBeanDoc()); 
	}

	public String genID()
	{
		return SAMLUtils.genID(ID_PREFIX);
	}
	
	public void sign(PrivateKey pk) throws DSigException 
	{
		sign(pk, null);
	}
	
	protected Document signInt(PrivateKey pk, X509Certificate []cert) 
		throws DSigException
	{
		DigSignatureUtil sign = new DigSignatureUtil();
		Document docToSign = getDOM();		
		NodeList nodes = docToSign.getFirstChild().getChildNodes();
		Node sibling = null;
		for (int i=0; i<nodes.getLength(); i++)
		{
			Node n = nodes.item(i);
			if (n.getLocalName().equals("Issuer"))
			{
				if (i+1 < nodes.getLength())
					sibling = nodes.item(i+1);
				else
					sibling = null;
				break;
			}
		}

		sign.genEnvelopedSignature(pk, null, cert, 
				docToSign, sibling, SamlTrustChecker.PROTOCOL_ID_QNAME);
		return docToSign;
	}
}
