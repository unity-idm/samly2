/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.unicore.samly2.trust;

import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import eu.emi.security.authn.x509.impl.X500NameUtils;
import eu.unicore.samly2.SAMLConstants;
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
	protected Map<String, Set<PublicKey>> trustedIssuers = new HashMap<>();

	public StrictSamlTrustChecker()
	{
		this(CheckingMode.REQUIRE_SIGNED_ASSERTION);
	}
	
	public StrictSamlTrustChecker(CheckingMode mode)
	{
		super(mode);
	}

	public void addTrustedIssuer(String samlId, String type, PublicKey trustedKey)
	{
		addTrustedIssuer(samlId, type, Collections.singletonList(trustedKey));
	}
	
	public void addTrustedIssuer(String samlId, String type, List<PublicKey> trustedKeys)
	{
		if (trustedKeys == null || trustedKeys.size() == 0)
			throw new IllegalArgumentException("Must have a non empty set of trusted keys");
		String key = getIssuerKey(type, samlId);
		Set<PublicKey> current = trustedIssuers.get(key);
		if (current == null)
		{
			current = new HashSet<>();
			trustedIssuers.put(key, current);
		}
		current.addAll(trustedKeys);
	}

	@Override
	protected List<PublicKey> establishKey(NameIDType issuer, SignatureType signature)
	{
		if (issuer == null)
			throw new SAMLTrustedKeyDiscoveryException("Issuer must be set when SAML artifact is signed");
		return getPublicKeys(issuer);
	}
	
	private List<PublicKey> getPublicKeys(NameIDType issuer)
	{
		String key = getIssuerKey(issuer.getFormat(), issuer.getStringValue());
		Set<PublicKey> trustedKeys = trustedIssuers.get(key);
		if (trustedKeys == null)
			throw new SAMLTrustedKeyDiscoveryException("The issuer of the SAML artifact " +
					"is not trusted: " + issuer.getStringValue());
		return new ArrayList<>(trustedKeys);
	}
	
	private String getIssuerKey(String format, String value) throws IllegalArgumentException
	{
		if (format == null)
			format = SAMLConstants.NFORMAT_ENTITY;
		if (format.equals(SAMLConstants.NFORMAT_ENTITY) || 
				format.equals(SAMLConstants.NFORMAT_PERSISTENT) ||
				format.equals(SAMLConstants.NFORMAT_UNSPEC) ||
				format.equals(SAMLConstants.NFORMAT_EMAIL))
			return format + "--_--" + value;
		if (format.equals(SAMLConstants.NFORMAT_DN))
			return format + "--_--" + X500NameUtils.getComparableForm(value);
		throw new IllegalArgumentException("Issuer name format is unknown: " + format);
	}
}
