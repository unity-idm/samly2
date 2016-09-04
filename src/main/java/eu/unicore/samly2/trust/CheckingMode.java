/*
 * Copyright (c) 2016 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.samly2.trust;

/**
 * Describes basic validation mode: whether signer response is enough or
 * whether assertion must be signed.
 * @author K. Benedyczak
 */
public enum CheckingMode 
{
	REQUIRE_SIGNED_RESPONSE_OR_ASSERTION, 
	REQUIRE_SIGNED_ASSERTION
}