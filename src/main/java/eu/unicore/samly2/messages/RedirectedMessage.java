/*
 * Copyright (c) 2021 Bixbit - Krzysztof Benedyczak. All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.samly2.messages;

import java.security.PublicKey;
import java.util.Optional;

import eu.unicore.samly2.binding.HttpRedirectBindingSupport;
import eu.unicore.security.dsig.DSigException;

public class RedirectedMessage implements SAMLVerifiableElement
{
	private final String rawQuery;
	
	public RedirectedMessage(String rawQuery)
	{
		this.rawQuery = rawQuery;
	}

	@Override
	public void verifySignature(PublicKey publicKey) throws DSigException
	{
		HttpRedirectBindingSupport.verifyDocumentSigature(rawQuery, publicKey);
	}

	@Override
	public boolean isSigned()
	{
		return HttpRedirectBindingSupport.isSigned(rawQuery);
	}

	@Override
	public Optional<PublicKey> getSignatureKey()
	{
		return Optional.empty();
	}
}
