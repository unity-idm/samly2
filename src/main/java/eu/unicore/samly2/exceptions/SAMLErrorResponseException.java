/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.unicore.samly2.exceptions;

import eu.unicore.samly2.SAMLConstants.Status;
import eu.unicore.samly2.SAMLConstants.SubStatus;


/**
 * Signals that the received response has not successful status. This exception might be specially handled.
 * @author K. Benedyczak
 */
public class SAMLErrorResponseException extends SAMLServerException
{

	private static final long serialVersionUID = 1L;

	public SAMLErrorResponseException(Status samlErrorId, String message, Throwable cause)
	{
		super(samlErrorId, message, cause);
		// TODO Auto-generated constructor stub
	}

	public SAMLErrorResponseException(Status samlErrorId, String message)
	{
		super(samlErrorId, message);
		// TODO Auto-generated constructor stub
	}

	public SAMLErrorResponseException(Status samlErrorId, SubStatus samlSubErrorId,
			String message, Throwable cause)
	{
		super(samlErrorId, samlSubErrorId, message, cause);
		// TODO Auto-generated constructor stub
	}

	public SAMLErrorResponseException(Status samlErrorId, SubStatus samlSubErrorId,
			String message)
	{
		super(samlErrorId, samlSubErrorId, message);
		// TODO Auto-generated constructor stub
	}

	public SAMLErrorResponseException(Status samlErrorId, SubStatus samlSubErrorId,
			Throwable cause)
	{
		super(samlErrorId, samlSubErrorId, cause);
		// TODO Auto-generated constructor stub
	}

	public SAMLErrorResponseException(Status samlErrorId, Throwable cause)
	{
		super(samlErrorId, cause);
		// TODO Auto-generated constructor stub
	}
}
