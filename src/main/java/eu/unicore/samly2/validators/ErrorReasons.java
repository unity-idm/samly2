/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.unicore.samly2.validators;

import java.util.ArrayList;
import java.util.List;

import xmlbeans.org.oasis.saml2.assertion.AssertionType;

/**
 * Maintains a list of errors (e.g. of assertions or multiple subject confirmations),
 * which may form a reason for ultimate validation error. 
 * @author K. Benedyczak
 */
public class ErrorReasons
{
	private List<String> errors = new ArrayList<String>();
	
	public void addConfirmationError(int n, String message)
	{
		errors.add("subject confirmation " + n + ": " + message);
	}
	
	public void addAssertionError(AssertionType assertion, String message)
	{
		errors.add("assertion " + assertion.getID() + ": " + message);
	}
	
	public int getSize()
	{
		return errors.size();
	}
	
	@Override
	public String toString()
	{
		return errors.toString();
	}
}
