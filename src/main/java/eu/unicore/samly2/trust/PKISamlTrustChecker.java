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

import eu.emi.security.authn.x509.ValidationResult;
import eu.emi.security.authn.x509.X509CertChainValidator;
import eu.emi.security.authn.x509.impl.X500NameUtils;
import eu.unicore.samly2.SAMLUtils;
import eu.unicore.samly2.exceptions.SAMLValidationException;
import eu.unicore.security.dsig.IdAttribute;

import xmlbeans.org.oasis.saml2.assertion.NameIDType;
import xmlbeans.org.w3.x2000.x09.xmldsig.SignatureType;

/**
 * Configures and performs checking whether consumer trusts the issuer of 
 * SAML assertion, request or response.
 * <p>
 * The process is based on checking of the digital signature. 
 * It is performed using a certificate validator. SAML request is considered trusted,
 * if it is correctly signed, there is issuer's certificate in signature and this certificate is trusted.
 * This class can be configured to accepted unsigned documents too.
 * @author K. Benedyczak
 */
public class PKISamlTrustChecker extends DsigSamlTrustCheckerBase
{
	protected X509CertChainValidator validator;
	protected boolean allowUnsigned;

	public PKISamlTrustChecker(X509CertChainValidator validator, boolean allowUnsigned)
	{
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
		
		ValidationResult res = validator.validate(issuerCC);
		if (!res.isValid())
			throw new SAMLValidationException("Signature issuer certificate (" +
					X500NameUtils.getReadableForm(issuerCC[0].getSubjectX500Principal())
					+ ") is not trusted: " + res.toShortString());
		
		return issuerCC[0].getPublicKey();
	}
	
	@Override
	protected void isCorrectlySigned(Document doc, PublicKey key, SignatureType signature, 
			List<Element> shallBeSigned, 
			IdAttribute idAttribute) throws SAMLValidationException
	{
		if (allowUnsigned && (signature == null || signature.isNil()))
			return;
		super.isCorrectlySigned(doc, key, signature, shallBeSigned, idAttribute);
	}
}
