/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.unicore.samly2.exceptions;

import eu.unicore.samly2.SAMLConstants;


/**
 * Signals problem which occurred during processing of SAML request.
 * This extension of {@link SAMLValidationException} holds additionally the SAML error status
 * and optionally substatus, so it can be used in SAML error response if needed.
 * 
 * This class is abstract - concrete subclasses should be used instead.
 * @author K. Benedyczak
 */
public class SAMLServerException extends SAMLValidationException
{
	private static final long serialVersionUID = 1L;
	protected SAMLConstants.Status samlErrorId;
	protected SAMLConstants.SubStatus samlSubErrorId;

	public SAMLServerException(SAMLConstants.Status samlErrorId, String message, Throwable cause)
	{
		super(message, cause);
		this.samlErrorId = samlErrorId;
	}

	public SAMLServerException(SAMLConstants.Status samlErrorId, String message)
	{
		super(message);
		this.samlErrorId = samlErrorId;
	}

	public SAMLServerException(SAMLConstants.Status samlErrorId, Throwable cause)
	{
		super(cause);
		this.samlErrorId = samlErrorId;
	}

	public SAMLServerException(SAMLConstants.Status samlErrorId, 
			SAMLConstants.SubStatus samlSubErrorId, String message, Throwable cause)
	{
		super(message, cause);
		this.samlErrorId = samlErrorId;
		this.samlSubErrorId = samlSubErrorId;
	}

	public SAMLServerException(SAMLConstants.Status samlErrorId, 
			SAMLConstants.SubStatus samlSubErrorId, String message)
	{
		super(message);
		this.samlErrorId = samlErrorId;
		this.samlSubErrorId = samlSubErrorId;
	}

	public SAMLServerException(SAMLConstants.Status samlErrorId, 
			SAMLConstants.SubStatus samlSubErrorId, Throwable cause)
	{
		super(cause);
		this.samlErrorId = samlErrorId;
		this.samlSubErrorId = samlSubErrorId;
	}

	/**
	 * @return the samlErrorId
	 */
	public SAMLConstants.Status getSamlErrorId()
	{
		return samlErrorId;
	}

	public void setSamlErrorId(SAMLConstants.Status samlErrorId)
	{
		this.samlErrorId = samlErrorId;
	}

	/**
	 * @return the samlSubErrorId
	 */
	public SAMLConstants.SubStatus getSamlSubErrorId()
	{
		return samlSubErrorId;
	}

	/**
	 * @param samlSubErrorId the samlSubErrorId to set
	 */
	public void setSamlSubErrorId(SAMLConstants.SubStatus samlSubErrorId)
	{
		this.samlSubErrorId = samlSubErrorId;
	}
}
