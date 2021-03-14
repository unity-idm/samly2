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
import eu.unicore.samly2.messages.SAMLVerifiableMessage;
import eu.unicore.security.dsig.DSigException;
import xmlbeans.org.oasis.saml2.assertion.NameIDType;

/**
 * New API (not {@link SamlTrustChecker} based) to verify whether message is trusted.
 */
public class MessagePublicKeyTrustChecker
{
	private static final Logger log = LogManager.getLogger(MessagePublicKeyTrustChecker.class);
	private final Function<NameIDType, List<PublicKey>> trustedKeys;
	
	public MessagePublicKeyTrustChecker(Function<NameIDType, List<PublicKey>> trustedKeys)
	{
		this.trustedKeys = trustedKeys;
	}

	public void verify(NameIDType issuer, SAMLVerifiableMessage message) throws SAMLValidationException
	{
		if (!message.isSigned())
			throw new SAMLValidationException("Message is not signed");
		Optional<PublicKey> signatureKey = message.getSignatureKey();
		if (signatureKey.isPresent())
			verifyWithGivenPublicKey(issuer, message, signatureKey.get());
		else
			verifyOverArbitraryPublicKey(issuer, message);
	}

	private void verifyOverArbitraryPublicKey(NameIDType issuer, SAMLVerifiableMessage message) throws SAMLValidationException
	{
		List<PublicKey> allKeys = getKeysOfIssuer(issuer);

		DSigException firstException = null;
		for (PublicKey candidateKey: allKeys)
		{
			try
			{
				message.verifySignature(candidateKey);
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

	private void verifyWithGivenPublicKey(NameIDType issuer, SAMLVerifiableMessage message, PublicKey publicKey) 
			throws SAMLValidationException
	{
		List<PublicKey> allKeys = getKeysOfIssuer(issuer);
		if (!allKeys.contains(publicKey))
			throw new SAMLValidationException("Message signed with a key " + publicKey 
					+ " not registered for " + issuer.getStringValue());
		try
		{
			message.verifySignature(publicKey);
		} catch (DSigException e)
		{
			throw new SAMLValidationException("Message signature is incorrect", e);
		}
	}	
}
