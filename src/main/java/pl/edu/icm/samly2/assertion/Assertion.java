/*
 * Copyright (c) 2007, 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on May 6, 2007
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package pl.edu.icm.samly2.assertion;

import java.io.IOException;

import org.apache.xmlbeans.XmlException;

import pl.edu.icm.samly2.elements.SAMLAttribute;
import pl.edu.icm.samly2.exceptions.SAMLParseException;

import xmlbeans.oasis.saml2.assertion.AssertionDocument;
import xmlbeans.oasis.saml2.assertion.AttributeStatementType;
import xmlbeans.oasis.saml2.assertion.AttributeType;


/**
 * SAML v2 assertion. It is generic, i.e. can represent any kind of assertion.
 * (identity, attribute, ...) but implements only subset of SAML constructs.
 * 
 * @author K. Benedyczak
 */
public class Assertion extends AbstractAssertion
{
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
}
