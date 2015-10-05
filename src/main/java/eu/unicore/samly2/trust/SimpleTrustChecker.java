/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.unicore.samly2.trust;

import java.security.PublicKey;
import java.security.cert.X509Certificate;

import xmlbeans.org.oasis.saml2.assertion.NameIDType;
import xmlbeans.org.w3.x2000.x09.xmldsig.SignatureType;
import eu.unicore.samly2.exceptions.SAMLValidationException;

/**
 * Trivial assertion checker - checks if signature is done by a specified certificate.
 * This class can be configured to accepted unsigned documents too.
 * @author K. Benedyczak
 */
public class SimpleTrustChecker extends OptionalDSigTrustChecker
{
	private X509Certificate issuerCert;

	public SimpleTrustChecker(X509Certificate issuerCertificate, boolean signatureOptional)
	{
		super(CheckingMode.REQUIRE_SIGNED_ASSERTION, signatureOptional);
		this.issuerCert = issuerCertificate;
	}
	
	@Override
	protected PublicKey establishKey(NameIDType issuer, SignatureType signature)
			throws SAMLValidationException
	{
		return issuerCert.getPublicKey();
	}
}