/*
 * Copyright (c) 2007, 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on Aug 21, 2007
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.samly2.exceptions;

import eu.unicore.samly2.SAMLConstants;


/**
 * @author K. Benedyczak
 */
@SuppressWarnings("serial")
public class SAMLVersionException extends SAMLProtocolException
{
	public SAMLVersionException(String subCode, String msg)
	{
		super(SAMLConstants.STATUS_VERSION_MISMATCH, subCode, msg);
	}
}
