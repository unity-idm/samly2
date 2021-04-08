/*
 * Copyright (c) 2021 Bixbit - Krzysztof Benedyczak. All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.samly2.messages;

import static eu.unicore.samly2.trust.SamlTrustChecker.PROTOCOL_ID_QNAME;

import org.apache.xmlbeans.XmlObject;

import xmlbeans.org.oasis.saml2.protocol.RequestAbstractType;
import xmlbeans.org.oasis.saml2.protocol.StatusResponseType;

/**
 * Message that was passed using a binding which allows for XML signatures, i.e. non-HTTP-redirect binding.
 */
public class XMLExpandedMessage extends XMLExpandedElement
{
	public XMLExpandedMessage(XmlObject messageXmlDoc, RequestAbstractType request)
	{
		super(messageXmlDoc, request.getSignature(), PROTOCOL_ID_QNAME);
	}

	public XMLExpandedMessage(XmlObject messageXmlDoc, StatusResponseType response)
	{
		super(messageXmlDoc, response.getSignature(), PROTOCOL_ID_QNAME);
	}
}
