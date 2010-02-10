/*
 * Copyright (c) 2007, 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on May 6, 2007
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.samly2.assertion;

import java.io.IOException;
import java.util.Calendar;

import org.apache.xmlbeans.XmlException;

import eu.unicore.samly2.elements.SAMLAttribute;
import eu.unicore.samly2.exceptions.SAMLParseException;

import xmlbeans.org.oasis.saml2.assertion.AssertionDocument;
import xmlbeans.org.oasis.saml2.assertion.AttributeStatementType;
import xmlbeans.org.oasis.saml2.assertion.AttributeType;
import xmlbeans.org.oasis.saml2.assertion.AuthnContextType;
import xmlbeans.org.oasis.saml2.assertion.AuthnStatementType;
import xmlbeans.org.oasis.saml2.assertion.SubjectLocalityType;


/**
 * SAML v2 assertion. It is generic, i.e. can represent any kind of assertion.
 * (identity, attribute, ...) but implements only subset of SAML constructs.
 * 
 * @author K. Benedyczak
 */
public class Assertion extends AbstractAssertion
{
	private static final long serialVersionUID = 1;

	public Assertion()
	{
	}
	
	public Assertion(AssertionDocument doc) throws SAMLParseException, 
		XmlException, IOException
	{
		super(doc);
	}

	public void addAttribute(SAMLAttribute at)
	{
		if (assertion.getAttributeStatementArray() == null ||
				assertion.getAttributeStatementArray().length == 0)
			assertion.addNewAttributeStatement();
		
		AttributeStatementType attrStatement = assertion.getAttributeStatementArray(0);
		
		AttributeType added = attrStatement.addNewAttribute();
		added.set(at.getXBean());
	}
	
	public void removeAttribute(int num)
	{
		assertion.removeAttributeStatement(num);
	}

	public AttributeStatementType[] getAttributes()
	{
		return assertion.getAttributeStatementArray();
	}

	public void addAuthStatement(Calendar authTime, AuthnContextType ctx, 
			String sessionIdx, Calendar sessionEnd, 
			SubjectLocalityType subjectLocation)
	{
		if (assertion.getAuthnStatementArray() == null || 
				assertion.getAuthnStatementArray().length == 0)
			assertion.addNewAuthnStatement();
		AuthnStatementType authStatement = assertion.getAuthnStatementArray(0);
		authStatement.setAuthnInstant(authTime);
		authStatement.setAuthnContext(ctx);
		if (sessionIdx != null)
			authStatement.setSessionIndex(sessionIdx);
		if (sessionEnd != null)
			authStatement.setSessionNotOnOrAfter(sessionEnd);
		if (subjectLocation != null)
			authStatement.setSubjectLocality(subjectLocation);
	}
	
	public void addAuthStatement(Calendar authTime, AuthnContextType ctx)
	{
		addAuthStatement(authTime, ctx, null, null, null);
	}
	
	public AuthnStatementType[] getAuthStatements()
	{
		return assertion.getAuthnStatementArray();
	}
}
