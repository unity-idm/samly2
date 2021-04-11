/*
 * Copyright (c) 2021 Bixbit - Krzysztof Benedyczak. All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.samly2.trust;

import java.security.PublicKey;
import java.util.Optional;
import java.util.function.Consumer;

import eu.unicore.samly2.messages.SAMLVerifiableElement;
import eu.unicore.security.dsig.DSigException;

class FakeVerifiableElement implements SAMLVerifiableElement
{
	private final PublicKey sigKey;
	private final boolean signed;
	private final Consumer<PublicKey> checker;

	FakeVerifiableElement(PublicKey sigKey, boolean signed, Consumer<PublicKey> checker)
	{
		this.sigKey = sigKey;
		this.signed = signed;
		this.checker = checker;
	}

	@Override
	public void verifySignature(PublicKey publicKey) throws DSigException
	{
		try
		{
			checker.accept(publicKey);
		} catch (Exception e)
		{
			throw new DSigException(e.toString());
		}
	}

	@Override
	public Optional<PublicKey> getSignatureKey()
	{
		return Optional.ofNullable(sigKey);
	}

	@Override
	public boolean isSigned()
	{
		return signed;
	}
}