/*
 * Copyright (c) 2021 Bixbit - Krzysztof Benedyczak. All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.samly2.messages;

import static eu.unicore.samly2.trust.SamlTrustChecker.PROTOCOL_ID_QNAME;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Optional;

import org.apache.xmlbeans.XmlObject;
import org.w3c.dom.Document;

import eu.unicore.samly2.SAMLUtils;
import eu.unicore.security.dsig.DSigException;
import eu.unicore.security.dsig.DigSignatureVerificator;
import xmlbeans.org.oasis.saml2.protocol.RequestAbstractType;
import xmlbeans.org.oasis.saml2.protocol.StatusResponseType;
import xmlbeans.org.w3.x2000.x09.xmldsig.SignatureType;

/**
 * Message that was passed using a binding which allows for XML signatures, i.e. non-HTTP-redirect binding.
 */
public class XMLExpandedMessage implements SAMLVerifiableElement
{
	private final XmlObject messageXmlDoc;
	private final SignatureType signature;

	public XMLExpandedMessage(XmlObject messageXmlDoc, RequestAbstractType request)
	{
		this(messageXmlDoc, request.getSignature());
	}

	public XMLExpandedMessage(XmlObject messageXmlDoc, StatusResponseType response)
	{
		this(messageXmlDoc, response.getSignature());
	}
	
	private XMLExpandedMessage(XmlObject messageXmlDoc, SignatureType signature)
	{
		this.messageXmlDoc = messageXmlDoc;
		this.signature = signature;
	}

	@Override
	public void verifySignature(PublicKey publicKey) throws DSigException
	{
		Document doc = (Document) messageXmlDoc.getDomNode();
		DigSignatureVerificator sign = new DigSignatureVerificator();
		if (!sign.verifyEnvelopedSignature(doc, Collections.singletonList(doc.getDocumentElement()), 
				PROTOCOL_ID_QNAME, publicKey))
			throw new DSigException("Signature is incorrect");
	}

	@Override
	public Optional<PublicKey> getSignatureKey()
	{
		X509Certificate[] issuerCC = SAMLUtils.getIssuerFromSignature(signature);
		return issuerCC == null ? Optional.empty() : Optional.of(issuerCC[0].getPublicKey());
	}

	@Override
	public boolean isSigned()
	{
		return signature != null;
	}
}
