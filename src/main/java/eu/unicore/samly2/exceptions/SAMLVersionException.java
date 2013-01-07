/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.unicore.samly2.exceptions;

import eu.unicore.samly2.SAMLConstants;


/**
 * Signals problems in validation of SAML request.
 * This extension of {@link SAMLValidationException} holds additionally the SAML error status
 * and optionally substatus, so it can be used in SAML error response if needed.
 * @author K. Benedyczak
 */
public class SAMLVersionException extends SAMLServerException
{
	private static final long serialVersionUID = 1L;

	public SAMLVersionException(String message, SAMLConstants.SubStatus samlSubErrorId)
	{
		super(SAMLConstants.Status.STATUS_VERSION_MISMATCH, samlSubErrorId, message);
	}

	public SAMLVersionException(String message)
	{
		super(SAMLConstants.Status.STATUS_VERSION_MISMATCH, message);
	}
}
