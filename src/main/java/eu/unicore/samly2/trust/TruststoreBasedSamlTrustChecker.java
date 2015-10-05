/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.unicore.samly2.trust;

import java.security.PublicKey;
import java.security.cert.X509Certificate;

import xmlbeans.org.oasis.saml2.assertion.NameIDType;
import xmlbeans.org.w3.x2000.x09.xmldsig.SignatureType;
import eu.emi.security.authn.x509.X509CertChainValidator;
import eu.emi.security.authn.x509.impl.X500NameUtils;
import eu.unicore.samly2.SAMLUtils;
import eu.unicore.samly2.exceptions.SAMLValidationException;

/**
 * Configures and performs checking whether consumer trusts the issuer of 
 * SAML assertion, request or response.
 * <p>
 * The process is based on checking of the digital signature. 
 * SAML request is considered trusted, if it is correctly signed, there is issuer's certificate 
 * in signature and this certificate is among trust anchors of a validator used to bootstrap 
 * the checker. This class is very similar to {@link StrictSamlTrustChecker}, but the trusted issuers
 * list is retrieved for each validation, therefore it can be modified at runtime when underlying validator's 
 * truststore is updated.
 * @author K. Benedyczak
 */
public class TruststoreBasedSamlTrustChecker extends DsigSamlTrustCheckerBase
{
	protected X509CertChainValidator validator;

	public TruststoreBasedSamlTrustChecker(X509CertChainValidator validator)
	{
		this(validator, CheckingMode.REQUIRE_SIGNED_ASSERTION);
	}
	
	public TruststoreBasedSamlTrustChecker(X509CertChainValidator validator, CheckingMode mode)
	{
		super(mode);
		this.validator = validator;
	}

	@Override
	protected PublicKey establishKey(NameIDType issuer, SignatureType signature) throws SAMLValidationException
	{
		X509Certificate[] issuerCC = SAMLUtils.getIssuerFromSignature(signature);
		if (issuerCC == null)
			throw new SAMLValidationException("Issuer certificate is not " +
					"set - it is impossible to verify the signature.");
		X509Certificate issuerC = issuerCC[0];
		X509Certificate[] trustedIssuers = validator.getTrustedIssuers();
		for (X509Certificate trusted: trustedIssuers)
			if (trusted.equals(issuerC))
				return issuerC.getPublicKey();
		throw new SAMLValidationException(
			"Issuer certificate is not issued by a trusted CA: " +
			X500NameUtils.getReadableForm(issuerC.getSubjectX500Principal()));
	}
}
