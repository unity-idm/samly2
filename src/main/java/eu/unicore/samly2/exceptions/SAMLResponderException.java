/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.unicore.samly2.exceptions;

import eu.unicore.samly2.SAMLConstants;


/**
 * Problem on the SAML responder side
 * @author K. Benedyczak
 */
public class SAMLResponderException extends SAMLServerException
{
	private static final long serialVersionUID = 1L;

	public SAMLResponderException(String message, Throwable cause)
	{
		super(SAMLConstants.Status.STATUS_RESPONDER, message, cause);
	}

	public SAMLResponderException(String message)
	{
		super(SAMLConstants.Status.STATUS_RESPONDER, message);
	}

	public SAMLResponderException(Throwable cause)
	{
		super(SAMLConstants.Status.STATUS_RESPONDER, cause);
	}

	public SAMLResponderException(SAMLConstants.SubStatus samlSubErrorId, String message, Throwable cause)
	{
		super(SAMLConstants.Status.STATUS_RESPONDER, samlSubErrorId, message, cause);
	}

	public SAMLResponderException(SAMLConstants.SubStatus samlSubErrorId, String message)
	{
		super(SAMLConstants.Status.STATUS_RESPONDER, samlSubErrorId, message);
	}

	public SAMLResponderException(SAMLConstants.SubStatus samlSubErrorId, Throwable cause)
	{
		super(SAMLConstants.Status.STATUS_RESPONDER, samlSubErrorId, cause);
	}
}
