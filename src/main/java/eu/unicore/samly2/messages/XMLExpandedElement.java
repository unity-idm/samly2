/*
 * Copyright (c) 2021 Bixbit - Krzysztof Benedyczak. All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.samly2.messages;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Optional;

import org.apache.xmlbeans.XmlObject;
import org.w3c.dom.Document;

import eu.unicore.samly2.SAMLUtils;
import eu.unicore.security.dsig.DSigException;
import eu.unicore.security.dsig.DigSignatureUtil;
import eu.unicore.security.dsig.IdAttribute;
import xmlbeans.org.w3.x2000.x09.xmldsig.SignatureType;

/**
 * Piece of XML that was passed using a binding which allows for XML signatures, i.e. non-HTTP-redirect binding.
 * Generic code that can be used for both messages and assertions.
 */
class XMLExpandedElement implements SAMLVerifiableElement
{
	private final XmlObject messageXmlDoc;
	private final SignatureType signature;
	private final IdAttribute idAttribute;

	XMLExpandedElement(XmlObject messageXmlDoc, SignatureType signature, IdAttribute idAttribute)
	{
		this.messageXmlDoc = messageXmlDoc;
		this.signature = signature;
		this.idAttribute = idAttribute;
	}

	@Override
	public void verifySignature(PublicKey publicKey) throws DSigException
	{
		Document doc = (Document) messageXmlDoc.getDomNode();
		DigSignatureUtil sign = new DigSignatureUtil();
		if (!sign.verifyEnvelopedSignature(doc, Collections.singletonList(doc.getDocumentElement()), 
				idAttribute, publicKey))
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
