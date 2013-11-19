/*
 * Copyright (c) 2007, 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on May 6, 2007
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.samly2.assertion;

import java.io.Serializable;

import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;

import eu.unicore.samly2.SAMLUtils;
import eu.unicore.samly2.validators.AssertionValidator;
import eu.unicore.security.dsig.Utils;

import xmlbeans.org.oasis.saml2.assertion.AssertionDocument;
import xmlbeans.org.oasis.saml2.assertion.AssertionType;
import xmlbeans.org.oasis.saml2.assertion.ConditionsType;
import xmlbeans.org.oasis.saml2.assertion.KeyInfoConfirmationDataType;
import xmlbeans.org.oasis.saml2.assertion.SubjectConfirmationType;
import xmlbeans.org.oasis.saml2.assertion.SubjectType;
import xmlbeans.org.w3.x2000.x09.xmldsig.KeyInfoType;
import xmlbeans.org.w3.x2000.x09.xmldsig.X509DataType;


/**
 * SAML v2 assertion parser. Helps to extract often needed information from SAML assertions.
 * It is assumed that the assertion was previously validated with {@link AssertionValidator}
 * or its extension.
 * 
 * @author K. Benedyczak
 */
public class AssertionParser implements Serializable
{
	private static final long serialVersionUID=1L;

	protected AssertionDocument assertionDoc;
	
	protected AssertionParser()
	{
	}
	
	public AssertionParser(AssertionDocument doc)
	{
		assertionDoc = doc;
	}

	public AssertionParser(AssertionType assertion)
	{
		assertionDoc = AssertionDocument.Factory.newInstance();
		assertionDoc.setAssertion(assertion);
	}

	/**
	 * Use {@link #getIssuerName()}.
	 * @return
	 */
	@Deprecated
	public String getIssuerDN()
	{
		return assertionDoc.getAssertion().getIssuer().getStringValue();
	}
	
	public String getIssuerName()
	{
		return assertionDoc.getAssertion().getIssuer().getStringValue();
	}

	/**
	 * Use {@link #getSubjectName()}
	 * @return
	 */
	@Deprecated
	public String getSubjectDN()
	{
		return getSubjectName();
	}

	public String getSubjectName()
	{
		return assertionDoc.getAssertion().getSubject().getNameID().getStringValue();
	}
	
	public String getIssuerNameFormat()
	{
		return assertionDoc.getAssertion().getIssuer().getFormat();
	}

	public String getSubjectNameFormat()
	{
		return assertionDoc.getAssertion().getSubject().getNameID().getFormat();
	}
	
	public boolean isSigned()
	{
		if (assertionDoc.getAssertion().getSignature() == null 
				|| assertionDoc.getAssertion().getSignature().isNil())
			return false;
		else return true;
	}
	
	public X509Certificate[] getIssuerFromSignature()
	{
		return SAMLUtils.getIssuerFromSignature(assertionDoc.getAssertion().getSignature());
	}

	public X509Certificate[] getSubjectFromConfirmation()
	{
		SubjectType subject = assertionDoc.getAssertion().getSubject();
		if (subject == null)
			return null;
		SubjectConfirmationType[] tt = subject.getSubjectConfirmationArray();
		if (tt == null || tt.length == 0)
			return null;
		SubjectConfirmationType confirmation = tt[0];
		if (confirmation == null)
			return null;
		KeyInfoConfirmationDataType confirData;
		try
		{
			confirData = (KeyInfoConfirmationDataType) 
				confirmation.getSubjectConfirmationData();
		} catch (ClassCastException e)
		{
			return null;
		}
		if (confirData == null)
			return null;
		KeyInfoType ki = confirData.getKeyInfoArray(0);
		if (ki == null)
			return null;
		X509DataType[] x509Data = ki.getX509DataArray();
		if (x509Data == null)
			return null;
		for (int i=0; i<x509Data.length; i++)
			if (x509Data[i].getX509CertificateArray().length > 0)
				return Utils.deserializeCertificateChain(
						x509Data[i].getX509CertificateArray());
		return null;
	}
	
	
	public AssertionDocument getXMLBeanDoc()
	{
		return assertionDoc;
	}

	public AssertionType getXMLBean()
	{
		return assertionDoc.getAssertion();
	}
	
	public int getProxyRestriction()
	{
		ConditionsType conditions = assertionDoc.getAssertion().getConditions();
		if (conditions == null || conditions.sizeOfProxyRestrictionArray() == 0)
			return -1;
		return conditions.getProxyRestrictionArray(0).getCount().intValue();
	}
	
	public Date getNotBefore()
	{
		ConditionsType conditions = assertionDoc.getAssertion().getConditions();
		Calendar c = conditions.getNotBefore();
		return c == null ? null : c.getTime();
	}

	public Date getNotOnOrAfter()
	{
		ConditionsType conditions = assertionDoc.getAssertion().getConditions();
		Calendar c = conditions.getNotOnOrAfter();
		return c == null ? null : c.getTime();
	}
}
