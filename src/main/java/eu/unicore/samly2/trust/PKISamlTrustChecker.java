/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.unicore.samly2.trust;

import java.security.PublicKey;
import java.security.cert.X509Certificate;

import xmlbeans.org.oasis.saml2.assertion.NameIDType;
import xmlbeans.org.w3.x2000.x09.xmldsig.SignatureType;
import eu.emi.security.authn.x509.ValidationResult;
import eu.emi.security.authn.x509.X509CertChainValidator;
import eu.emi.security.authn.x509.impl.X500NameUtils;
import eu.unicore.samly2.SAMLUtils;
import eu.unicore.samly2.exceptions.SAMLValidationException;

/**
 * Configures and performs checking whether consumer trusts the issuer of 
 * SAML assertion, request or response.
 * <p>
 * The process is based on checking of the digital signature. 
 * It is performed using a certificate validator. SAML request is considered trusted,
 * if it is correctly signed, there is issuer's certificate in signature and this certificate is trusted.
 * This class can be configured to accepted unsigned documents too.
 * <p>
 * Note that this is going to work when the validator's truststore contains certificates of CAs issuing
 * certificates of SAML issuers. This won't accept SAML issuers whose certificates are put to the 
 * validator's truststore, as according to X.509 path validation, such situation is invalid. If the latter
 * result is desired use {@link TruststoreBasedSamlTrustChecker}.
 * @author K. Benedyczak
 */
public class PKISamlTrustChecker extends OptionalDSigTrustChecker
{
	protected X509CertChainValidator validator;
	protected boolean allowUnsigned;

	public PKISamlTrustChecker(X509CertChainValidator validator, boolean allowUnsigned)
	{
		super(CheckingMode.REQUIRE_SIGNED_ASSERTION, allowUnsigned);
		this.validator = validator;
		this.allowUnsigned = allowUnsigned;
	}

	public PKISamlTrustChecker(X509CertChainValidator validator)
	{
		this(validator, false);
	}

	@Override
	protected PublicKey establishKey(NameIDType issuer, SignatureType signature) throws SAMLValidationException
	{
		X509Certificate[] issuerCC = SAMLUtils.getIssuerFromSignature(signature);
		if (issuerCC == null)
			throw new SAMLValidationException("Issuer certificate is not " +
					"set - it is impossible to verify the signature.");
		
		ValidationResult result = validator.validate(issuerCC);
		if (!result.isValid())
			throw new SAMLValidationException(
				"Issuer certificate is not issued by a trusted CA: " +
				X500NameUtils.getReadableForm(issuerCC[0].getSubjectX500Principal()) + 
				" Cause: " + result.toShortString());
		
		return issuerCC[0].getPublicKey();
	}
}
