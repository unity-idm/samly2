/*
 * Copyright (c) 2021 Bixbit - Krzysztof Benedyczak. All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.samly2.messages;

import java.security.PublicKey;
import java.util.Optional;

import eu.unicore.security.dsig.DSigException;

/**
 * An input message which can have its signature checked (in transport dependent way). 
 *  
 */
public interface SAMLVerifiableMessage
{
	void verifySignature(PublicKey publicKey) throws DSigException;
	Optional<PublicKey> getSignatureKey();
	boolean isSigned();
} 
