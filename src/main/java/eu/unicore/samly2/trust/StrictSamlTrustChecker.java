/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.unicore.samly2.trust;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import eu.emi.security.authn.x509.impl.X500NameUtils;
import eu.unicore.samly2.SAMLConstants;
import eu.unicore.samly2.SAMLUtils;
import eu.unicore.samly2.exceptions.SAMLValidationException;

import xmlbeans.org.oasis.saml2.assertion.NameIDType;
import xmlbeans.org.w3.x2000.x09.xmldsig.SignatureType;

/**
 * Configures and performs checking whether consumer trusts the issuer of 
 * SAML assertion, request or response.
 * <p>
 * The process is based on checking of the digital signature and the artifact issuer. 
 * It is performed using the following input: a list of trusted issuers and, for each issuer,
 * a list of trusted public keys.
 * The signature must be produced by one of the public keys of the issuer declared in
 * the artifact.   
 * @author K. Benedyczak
 */
public class StrictSamlTrustChecker extends DsigSamlTrustCheckerBase
{
	protected Map<String, List<PublicKey>> trustedIssuers = new HashMap<String, List<PublicKey>>();
	
	public void addTrustedIssuer(String samlId, String type, PublicKey trustedKey)
	{
		addTrustedIssuer(samlId, type, Collections.singletonList(trustedKey));
	}
	
	public void addTrustedIssuer(String samlId, String type, List<PublicKey> trustedKeys)
	{
		if (trustedKeys == null || trustedKeys.size() == 0)
			throw new IllegalArgumentException("Must have a non empty set of trusted keys");
		if (SAMLConstants.NFORMAT_DN.equals(type))
			samlId = X500NameUtils.getComparableForm(samlId);
		trustedIssuers.put(type+"--_--"+samlId, trustedKeys);
	}

	@Override
	protected PublicKey establishKey(NameIDType issuer, SignatureType signature) throws SAMLValidationException
	{
		if (issuer == null)
			throw new SAMLValidationException("Issuer must be set when SAML artifact is signed");
		List<PublicKey> keys = getPublicKeys(issuer);
		X509Certificate[] issuerCC = SAMLUtils.getIssuerFromSignature(signature);
		if (issuerCC == null)
		{
			if (keys.size() == 1)
				return keys.get(0);
			else
				throw new SAMLValidationException("Issuer certificate is not " +
						"set and the issuer '"+ issuer.getStringValue() + 
						"' has several trusted public keys - it is undefined which was used for signing.");
		} else
		{
			for (PublicKey trustedKey: keys)
				if (trustedKey.equals(issuerCC[0].getPublicKey()))
					return trustedKey;
			throw new SAMLValidationException("Issuer certificate is not " +
					"among trusted certificates for the issuer'" + issuer.getStringValue() + 
						"' Untrusted issuer certificate subject is: " + 
					X500NameUtils.getReadableForm(issuerCC[0].getSubjectX500Principal()));
		}
	}
	
	protected List<PublicKey> getPublicKeys(NameIDType issuer) throws SAMLValidationException
	{
		String key = getIssuerKey(issuer);
		List<PublicKey> trustedKeys = trustedIssuers.get(key);
		if (trustedKeys == null)
			throw new SAMLValidationException("The issuer of the SAML artifact " +
					"is not trusted: " + issuer.getStringValue());
		return trustedKeys;
	}
	
	protected String getIssuerKey(NameIDType issuer) throws SAMLValidationException
	{
		String format = issuer.getFormat();
		if (format == null ||
				format.equals(SAMLConstants.NFORMAT_ENTITY) || 
				format.equals(SAMLConstants.NFORMAT_PERSISTENT) ||
				format.equals(SAMLConstants.NFORMAT_UNSPEC) ||
				format.equals(SAMLConstants.NFORMAT_EMAIL))
			return format + "--_--" + issuer.getStringValue();
		if (issuer.getFormat().equals(SAMLConstants.NFORMAT_DN))
			return format + "--_--" + X500NameUtils.getComparableForm(issuer.getStringValue());
		throw new SAMLValidationException("Issuer name format is unknown: " + issuer.getFormat());
	}
}
