/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.unicore.samly2.trust;

import java.security.PublicKey;
import java.util.Collections;
import java.util.List;

import org.apache.xmlbeans.XmlObject;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import eu.unicore.samly2.exceptions.SAMLValidationException;
import eu.unicore.security.dsig.DSigException;
import eu.unicore.security.dsig.DigSignatureUtil;
import eu.unicore.security.dsig.IdAttribute;

import xmlbeans.org.oasis.saml2.assertion.AssertionDocument;
import xmlbeans.org.oasis.saml2.assertion.AssertionType;
import xmlbeans.org.oasis.saml2.assertion.NameIDType;
import xmlbeans.org.oasis.saml2.protocol.RequestAbstractType;
import xmlbeans.org.oasis.saml2.protocol.StatusResponseType;
import xmlbeans.org.w3.x2000.x09.xmldsig.SignatureType;

/**
 * Configures and performs checking whether consumer trusts the issuer of 
 * SAML assertion, request or response.
 * <p>
 * The process is based on checking of the digital signature. 
 * Usful for extending.
 * @author K. Benedyczak
 */
public abstract class DsigSamlTrustCheckerBase implements SamlTrustChecker
{
	@Override
	public boolean isSignatureRequired()
	{
		return true;
	}
	
	@Override
	public void checkTrust(AssertionDocument assertionDoc) throws SAMLValidationException
	{
		AssertionType assertion = assertionDoc.getAssertion();
		checkCommon(assertionDoc, assertion.getIssuer(), assertion.getSignature(), ASSERTION_ID_QNAME);
	}

	@Override
	public void checkTrust(XmlObject responseDoc, StatusResponseType response) throws SAMLValidationException
	{
		checkCommon(responseDoc, response.getIssuer(), response.getSignature(), PROTOCOL_ID_QNAME);
	}

	@Override
	public void checkTrust(XmlObject requestDoc, RequestAbstractType request) throws SAMLValidationException
	{
		checkCommon(requestDoc, request.getIssuer(), request.getSignature(), PROTOCOL_ID_QNAME);
	}
	
	protected void checkCommon(XmlObject xmlbeansDoc, NameIDType issuer, 
			SignatureType signature, IdAttribute idAttribute) throws SAMLValidationException
	{
		PublicKey publicKey = establishKey(issuer, signature);
		
		Document doc = (Document) xmlbeansDoc.getDomNode();
		isCorrectlySigned(doc, publicKey, 
				signature, 
				Collections.singletonList(doc.getDocumentElement()), 
				idAttribute);
	}
	
	protected void isCorrectlySigned(Document doc, PublicKey key, SignatureType signature, 
			List<Element> shallBeSigned, 
			IdAttribute idAttribute) throws SAMLValidationException
	{
		if (signature == null || signature.isNil())
			throw new SAMLValidationException("XML document is not signed");
		DigSignatureUtil sign;
		try
		{
			sign = new DigSignatureUtil();
			if (!sign.verifyEnvelopedSignature(doc, shallBeSigned, idAttribute, key))
				throw new SAMLValidationException("Signature is incorrect");
		} catch (DSigException e)
		{
			throw new SAMLValidationException("Signature verification failed", e);
		}
	}

	protected abstract PublicKey establishKey(NameIDType issuer, SignatureType signature) throws SAMLValidationException;
}
