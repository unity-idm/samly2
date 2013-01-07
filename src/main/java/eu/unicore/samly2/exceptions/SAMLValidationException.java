/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.unicore.samly2.exceptions;

/**
 * Signals problems in SAML validation.
 * @author K. Benedyczak
 */
public class SAMLValidationException extends Exception
{
	private static final long serialVersionUID = 1L;

	public SAMLValidationException(String message, Throwable cause)
	{
		super(message, cause);
	}

	public SAMLValidationException(String message)
	{
		super(message);
	}

	public SAMLValidationException(Throwable cause)
	{
		super(cause);
	}
}
