/*
 * Copyright (c) 2021 Bixbit - Krzysztof Benedyczak. All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.samly2.messages;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Optional;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import eu.unicore.samly2.SAMLUtils;
import eu.unicore.samly2.trust.SamlTrustChecker;
import eu.unicore.security.dsig.DSigException;
import eu.unicore.security.dsig.DigSignatureVerificator;
import xmlbeans.org.oasis.saml2.assertion.AssertionDocument;

/**
 * Assertion which can have its signature checked
 */
public class XMLExpandedAssertion implements SAMLVerifiableElement
{
	private final SAMLUtils.XMLBeansWithDom<AssertionDocument> assertionDoc;

	public XMLExpandedAssertion(SAMLUtils.XMLBeansWithDom<AssertionDocument> assertionDoc)
	{
		this.assertionDoc = assertionDoc;
	}

	@Override
	public void verifySignature(PublicKey publicKey) throws DSigException
	{
		DigSignatureVerificator verificator = new DigSignatureVerificator();
		boolean signatureValid;
		if (assertionDoc.domNode instanceof Element)
		{
			Element element = (Element) assertionDoc.domNode;
			signatureValid = verificator.verifyEnvelopedSignature(element, Collections.singletonList(element),
					SamlTrustChecker.ASSERTION_ID_QNAME, publicKey);
		} else
		{
			Document doc = (Document) assertionDoc.domNode;
			signatureValid = verificator.verifyEnvelopedSignature(doc, 
					Collections.singletonList(doc.getDocumentElement()),
					SamlTrustChecker.ASSERTION_ID_QNAME, publicKey);
		}
		if (!signatureValid)
			throw new DSigException("Signature is incorrect");
	}

	@Override
	public Optional<PublicKey> getSignatureKey()
	{
		X509Certificate[] issuerCC = SAMLUtils.getIssuerFromSignature(assertionDoc.xmlBean.getAssertion().getSignature());
		return issuerCC == null ? Optional.empty() : Optional.of(issuerCC[0].getPublicKey());
	}

	@Override
	public boolean isSigned()
	{
		return assertionDoc.xmlBean.getAssertion().getSignature() != null;
	}
}
