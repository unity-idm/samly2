/*
 * Copyright (c) 2021 Bixbit - Krzysztof Benedyczak. All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.samly2.trust;

import java.security.PublicKey;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import eu.unicore.samly2.exceptions.SAMLValidationException;
import eu.unicore.samly2.messages.SAMLVerifiableElement;
import eu.unicore.security.dsig.DSigException;
import xmlbeans.org.oasis.saml2.assertion.NameIDType;

/**
 * Implements checking of signatures on {@link SAMLVerifiableElement} objects. It is configured with a provider that can
 * supply trusted keys. If verified object doesn't specify which key was used for signing then all trusted keys are tried. 
 */
public class SignatureChecker
{
	private static final Logger log = LogManager.getLogger(SignatureChecker.class);
	private final Function<NameIDType, List<PublicKey>> trustedKeys;
	
	public SignatureChecker(Function<NameIDType, List<PublicKey>> trustedKeys)
	{
		this.trustedKeys = trustedKeys;
	}

	public void verify(NameIDType issuer, SAMLVerifiableElement verifiableElement) throws SAMLValidationException
	{
		if (!verifiableElement.isSigned())
			throw new SAMLValidationException("Message is not signed");
		Optional<PublicKey> signatureKey = verifiableElement.getSignatureKey();
		if (signatureKey.isPresent())
			verifyWithGivenPublicKey(issuer, verifiableElement, signatureKey.get());
		else
			verifyOverArbitraryPublicKey(issuer, verifiableElement);
	}

	private void verifyOverArbitraryPublicKey(NameIDType issuer, SAMLVerifiableElement verifiableElement) throws SAMLValidationException
	{
		List<PublicKey> allKeys = getKeysOfIssuer(issuer);

		DSigException firstException = null;
		for (PublicKey candidateKey: allKeys)
		{
			try
			{
				verifiableElement.verifySignature(candidateKey);
				return;
			} catch (DSigException e)
			{
				if (firstException == null)
					firstException = e;
				log.debug("Checking signature using key " + candidateKey + " failed", e);
			}
		}
		throw new SAMLValidationException("Message signature is incorrect or is not signed by a registered "
				+ "public key for the issuer " + issuer.getStringValue(), firstException);
	}

	private List<PublicKey> getKeysOfIssuer(NameIDType issuer) throws SAMLValidationException
	{
		List<PublicKey> allKeys = trustedKeys.apply(issuer);
		if (allKeys == null || allKeys.isEmpty())
			throw new SAMLValidationException("Message issuer " + issuer.getStringValue() + " is not trusted");
		return allKeys;
	}

	private void verifyWithGivenPublicKey(NameIDType issuer, SAMLVerifiableElement verifiableElement, PublicKey publicKey) 
			throws SAMLValidationException
	{
		List<PublicKey> allKeys = getKeysOfIssuer(issuer);
		if (!allKeys.contains(publicKey))
			throw new SAMLValidationException("Message signed with a key " + publicKey 
					+ " not registered for " + issuer.getStringValue());
		try
		{
			verifiableElement.verifySignature(publicKey);
		} catch (DSigException e)
		{
			throw new SAMLValidationException("Message signature is incorrect", e);
		}
	}	
}
