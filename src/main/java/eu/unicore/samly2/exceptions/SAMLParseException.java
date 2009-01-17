/*
 * Copyright (c) 2007, 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on Aug 21, 2007
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.samly2.exceptions;


/**
 * @author K. Benedyczak
 */
@SuppressWarnings("serial")
public class SAMLParseException extends Exception
{
	public SAMLParseException(String msg)
	{
		super(msg);
	}
}
