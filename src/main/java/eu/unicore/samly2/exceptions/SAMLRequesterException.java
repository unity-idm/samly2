/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.unicore.samly2.exceptions;

import eu.unicore.samly2.SAMLConstants;


/**
 * Problem on the requestor side.
 * @author K. Benedyczak
 */
public class SAMLRequesterException extends SAMLServerException
{
	private static final long serialVersionUID = 1L;

	public SAMLRequesterException(String message, Throwable cause)
	{
		super(SAMLConstants.Status.STATUS_REQUESTER, message, cause);
	}

	public SAMLRequesterException(String message)
	{
		super(SAMLConstants.Status.STATUS_REQUESTER, message);
	}

	public SAMLRequesterException(Throwable cause)
	{
		super(SAMLConstants.Status.STATUS_REQUESTER, cause);
	}

	public SAMLRequesterException(SAMLConstants.SubStatus samlSubErrorId, String message, Throwable cause)
	{
		super(SAMLConstants.Status.STATUS_REQUESTER, samlSubErrorId, message, cause);
	}

	public SAMLRequesterException(SAMLConstants.SubStatus samlSubErrorId, String message)
	{
		super(SAMLConstants.Status.STATUS_REQUESTER, samlSubErrorId, message);
	}

	public SAMLRequesterException(SAMLConstants.SubStatus samlSubErrorId, Throwable cause)
	{
		super(SAMLConstants.Status.STATUS_REQUESTER, samlSubErrorId, cause);
	}
}
