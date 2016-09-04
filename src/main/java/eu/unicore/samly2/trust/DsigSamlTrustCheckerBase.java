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
 * Useful for extending.
 * @author K. Benedyczak
 */
public abstract class DsigSamlTrustCheckerBase implements SamlTrustChecker
{
	private CheckingMode mode;
	
	public DsigSamlTrustCheckerBase(CheckingMode mode)
	{
		this.mode = mode;
	}

	@Override
	public CheckingMode getCheckingMode()
	{
		return mode;
	}
	
	@Override
	public void checkTrust(AssertionDocument assertionDoc, ResponseTrustCheckResult responseCheckResult) 
			throws SAMLValidationException
	{
		AssertionType assertion = assertionDoc.getAssertion();
		
		if (mode == CheckingMode.REQUIRE_SIGNED_ASSERTION)
			checkRequiredSignature(assertionDoc, assertion.getIssuer(), assertion.getSignature(), 
					ASSERTION_ID_QNAME);
		else
			checkOptionalSignature(assertionDoc, assertion.getIssuer(), assertion.getSignature(), 
					ASSERTION_ID_QNAME);
	}

	@Override
	public void checkTrust(AssertionDocument assertionDoc) throws SAMLValidationException
	{
		checkTrust(assertionDoc, new ResponseTrustCheckResult(false));
	}
	
	@Override
	public ResponseTrustCheckResult checkTrust(XmlObject responseDoc, StatusResponseType response) 
			throws SAMLValidationException
	{
		SignatureType signature = response.getSignature();
		if (signature == null || signature.isNil())
			return new ResponseTrustCheckResult(false);
		
		checkSignature(responseDoc, response.getIssuer(), signature, PROTOCOL_ID_QNAME);
		return new ResponseTrustCheckResult(true);
	}

	@Override
	public void checkTrust(XmlObject requestDoc, RequestAbstractType request) throws SAMLValidationException
	{
		checkRequiredSignature(requestDoc, request.getIssuer(), request.getSignature(), PROTOCOL_ID_QNAME);
	}

	protected void checkRequiredSignature(XmlObject xmlbeansDoc, NameIDType issuer, 
			SignatureType signature, IdAttribute idAttribute) throws SAMLValidationException
	{
		if (signature == null || signature.isNil())
			throw new SAMLValidationException("SAML document is not signed and the policy requires a signature");
		checkSignature(xmlbeansDoc, issuer, signature, idAttribute);
	}

	protected void checkOptionalSignature(XmlObject xmlbeansDoc, NameIDType issuer, 
			SignatureType signature, IdAttribute idAttribute) throws SAMLValidationException
	{
		if (signature == null || signature.isNil())
			return;
		checkSignature(xmlbeansDoc, issuer, signature, idAttribute);
	}
	
	protected void checkSignature(XmlObject xmlbeansDoc, NameIDType issuer, 
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
