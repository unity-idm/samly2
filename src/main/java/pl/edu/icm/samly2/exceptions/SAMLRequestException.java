/*
 * Copyright (c) 2007, 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on Aug 21, 2007
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package pl.edu.icm.samly2.exceptions;

import pl.edu.icm.samly2.SAMLConstants;

/**
 * @author K. Benedyczak
 */
@SuppressWarnings("serial")
public class SAMLRequestException extends SAMLProtocolException
{
	public SAMLRequestException(String subCode, String msg)
	{
		super(SAMLConstants.STATUS_REQUESTER, subCode, msg);
	}
}
