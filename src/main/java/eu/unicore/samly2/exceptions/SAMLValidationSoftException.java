/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.unicore.samly2.exceptions;


/**
 * Singals problems in SAML validation. This subclass is used to signal problems 
 * which are not critical. I.e. if an assertion being validated 
 * doesn't fulfill some requirements, but it is generally valid, the overall validation
 * of a response can continue and check if other, fully valid assertions are available. 
 * 
 * @author K. Benedyczak
 */
public class SAMLValidationSoftException extends SAMLValidationException
{
	private static final long serialVersionUID = 1L;

	public SAMLValidationSoftException(String message, Throwable cause)
	{
		super(message, cause);
	}

	public SAMLValidationSoftException(Throwable cause)
	{
		super(cause);
	}

	public SAMLValidationSoftException(String message)
	{
		super(message);
	}

}
