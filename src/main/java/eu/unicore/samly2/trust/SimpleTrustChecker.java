/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.unicore.samly2.trust;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.List;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import xmlbeans.org.oasis.saml2.assertion.NameIDType;
import xmlbeans.org.w3.x2000.x09.xmldsig.SignatureType;
import eu.unicore.samly2.exceptions.SAMLValidationException;
import eu.unicore.security.dsig.IdAttribute;

/**
 * Trivial assertion checker - checks if signature is done by a specified certificate.
 * This class can be configured to accepted unsigned documents too.
 * @author K. Benedyczak
 */
public class SimpleTrustChecker extends DsigSamlTrustCheckerBase
{
	private X509Certificate issuerCert;
	private boolean signatureOptional;

	public SimpleTrustChecker(X509Certificate issuerCertificate, boolean signatureOptional)
	{
		this.issuerCert = issuerCertificate;
		this.signatureOptional = signatureOptional;
	}
	
	@Override
	protected PublicKey establishKey(NameIDType issuer, SignatureType signature)
			throws SAMLValidationException
	{
		return issuerCert.getPublicKey();
	}
	
	@Override
	protected void isCorrectlySigned(Document doc, PublicKey key, SignatureType signature, 
			List<Element> shallBeSigned, 
			IdAttribute idAttribute) throws SAMLValidationException
	{
		if (signatureOptional && (signature == null || signature.isNil()))
			return;
		super.isCorrectlySigned(doc, key, signature, shallBeSigned, idAttribute);
	}
}