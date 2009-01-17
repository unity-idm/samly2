/*
 * Copyright (c) 2007, 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on Aug 21, 2007
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package pl.edu.icm.samly2.exceptions;

/**
 * Parent exeption to signalize SAML protocol error.
 * @author K. Benedyczak
 */
@SuppressWarnings("serial")
public class SAMLProtocolException extends Exception
{
	private String code;
	private String subCode;
	
	public String getSubCode()
	{
		return subCode;
	}

	public SAMLProtocolException(String code, String subCode, String msg)
	{
		super(msg);
		this.code = code;
		this.subCode = subCode;
	}

	public String getCode()
	{
		return code;
	}
}
