/*
 * Copyright (c) 2007, 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on May 6, 2007
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.samly2.assertion;

import java.io.Serializable;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.TimeZone;

import javax.xml.namespace.QName;

import org.apache.xmlbeans.XmlCursor;
import org.apache.xmlbeans.XmlException;
import org.apache.xmlbeans.XmlObject;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import eu.emi.security.authn.x509.impl.X500NameUtils;
import eu.unicore.samly2.SAMLConstants;
import eu.unicore.samly2.SAMLUtils;
import eu.unicore.samly2.elements.SAMLAttribute;
import eu.unicore.samly2.trust.SamlTrustChecker;
import eu.unicore.security.dsig.DSigException;
import eu.unicore.security.dsig.DigSignatureUtil;

import xmlbeans.org.oasis.saml2.assertion.AssertionDocument;
import xmlbeans.org.oasis.saml2.assertion.AssertionType;
import xmlbeans.org.oasis.saml2.assertion.AttributeStatementType;
import xmlbeans.org.oasis.saml2.assertion.AttributeType;
import xmlbeans.org.oasis.saml2.assertion.AuthnContextType;
import xmlbeans.org.oasis.saml2.assertion.AuthnStatementType;
import xmlbeans.org.oasis.saml2.assertion.ConditionAbstractType;
import xmlbeans.org.oasis.saml2.assertion.ConditionsType;
import xmlbeans.org.oasis.saml2.assertion.KeyInfoConfirmationDataType;
import xmlbeans.org.oasis.saml2.assertion.NameIDType;
import xmlbeans.org.oasis.saml2.assertion.SubjectConfirmationType;
import xmlbeans.org.oasis.saml2.assertion.SubjectLocalityType;
import xmlbeans.org.oasis.saml2.assertion.SubjectType;
import xmlbeans.org.w3.x2000.x09.xmldsig.KeyInfoType;


/**
 * SAML v2 assertion. It is generic, i.e. can represent any kind of assertion 
 * (identity, attribute, ...) but implements only subset of SAML constructs.
 * There is no code related to statements here.
 * 
 * @author K. Benedyczak
 */
public class Assertion extends AssertionParser implements Serializable
{
	private static final long serialVersionUID=1L;

	private static String ID_PREFIX = "SAMLY2lib_assert_";
	
	public Assertion()
	{
		assertionDoc = AssertionDocument.Factory.newInstance();
		AssertionType assertion = assertionDoc.addNewAssertion();
		assertion.setVersion(SAMLConstants.SAML2_VERSION);
		assertion.setIssueInstant(Calendar.getInstance(TimeZone.getTimeZone("UTC")));
		assertion.setID(SAMLUtils.genID(ID_PREFIX));
	}

	public Assertion(AssertionDocument doc)
	{
		super(doc);
	}
	
	public void setX509Issuer(String issuerName)
	{
		//This is on purpose: this form should be OK w.r.t. latest XML DSig spec
		//and the 2002 one was simply invalid.
		String dn = X500NameUtils.getPortableRFC2253Form(issuerName);
		NameIDType issuerN = NameIDType.Factory.newInstance();
		issuerN.setFormat(SAMLConstants.NFORMAT_DN);
		issuerN.setStringValue(dn);
		assertionDoc.getAssertion().setIssuer(issuerN);
	}

	public void setIssuer(String value, String format)
	{
		NameIDType issuer = NameIDType.Factory.newInstance();
		issuer.setStringValue(value);
		issuer.setFormat(format);
		assertionDoc.getAssertion().setIssuer(issuer);
	}
	
	public void setX509Subject(String subjectName)
	{
		String dn = X500NameUtils.getPortableRFC2253Form(subjectName);
		NameIDType subjectN = NameIDType.Factory.newInstance();
		subjectN.setFormat(SAMLConstants.NFORMAT_DN);
		subjectN.setStringValue(dn);

		SubjectType subjectT = SubjectType.Factory.newInstance();
		subjectT.setNameID(subjectN);
		assertionDoc.getAssertion().setSubject(subjectT);
	}

	public void setSubject(NameIDType subject)
	{
		SubjectType subjectT = SubjectType.Factory.newInstance();
		subjectT.setNameID(subject);
		assertionDoc.getAssertion().setSubject(subjectT);
	}

	public void setSubject(SubjectType subject)
	{
		//The following line should be enough here but unfortunately the produced
		//XML has not prefix set (uses default NS defined in it). 
		//It is perfectly OK, but unicore gateway 
		//(prior to version 6.3.0) can't handle this situation
		//and adds the prefix what spoils the signature. So we do the copy manually
		//- this way xmlbeans adds prefixes.
		
		//assertion.setSubject(subject);
		
		//---- hack start
		if (assertionDoc.getAssertion().isSetSubject())
			assertionDoc.getAssertion().unsetSubject();
		SubjectType added = assertionDoc.getAssertion().addNewSubject();
		if (subject.isSetNameID())
			added.setNameID(subject.getNameID());
		if (subject.isSetEncryptedID())
			added.setEncryptedID(subject.getEncryptedID());
		if (subject.isSetBaseID())
			added.setBaseID(subject.getBaseID());
		if (subject.sizeOfSubjectConfirmationArray() > 0)
			added.setSubjectConfirmationArray(subject.getSubjectConfirmationArray());
		//----- hack end
	}

	public void setHolderOfKeyConfirmation(X509Certificate[] certificates) 
		throws CertificateEncodingException
	{
		setConfirmation(certificates, SAMLConstants.CONFIRMATION_HOLDER_OF_KEY);
	}

	public void setSenderVouchesX509Confirmation(X509Certificate[] certificates) 
		throws CertificateEncodingException
	{
		setConfirmation(certificates, SAMLConstants.CONFIRMATION_SENDER_VOUCHES);
	}

	private void setConfirmation(X509Certificate[] certificates, String method) 
		throws CertificateEncodingException
	{
		SubjectType subject = assertionDoc.getAssertion().getSubject();
		SubjectConfirmationType confirmation = subject.addNewSubjectConfirmation();
		confirmation.setMethod(method);
		KeyInfoConfirmationDataType confirData = 
			KeyInfoConfirmationDataType.Factory.newInstance();
		KeyInfoType ki = DigSignatureUtil.generateX509KeyInfo(certificates);
		confirData.setKeyInfoArray(new KeyInfoType[] {ki});
		confirmation.setSubjectConfirmationData(confirData);
	}
	
	
	public void updateIssueTime()
	{
		assertionDoc.getAssertion().setIssueInstant(Calendar.getInstance(TimeZone.getTimeZone("UTC")));		
	}

	protected ConditionsType getOrCreateConditions()
	{
		ConditionsType conditions = assertionDoc.getAssertion().getConditions();
		if (conditions == null)
			return assertionDoc.getAssertion().addNewConditions();
		return conditions;
	}
	
	public void setTimeConditions(Date notBefore, Date notOnOrAfter)
	{
		Calendar c = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
		ConditionsType conditions = getOrCreateConditions();
		if (notBefore != null)
		{
			c.setTime(notBefore);
			conditions.setNotBefore(c);
		} else
		{
			if (conditions.isSetNotBefore())
				conditions.unsetNotBefore();
		}
		if (notOnOrAfter != null)
		{
			c.setTime(notOnOrAfter);
			conditions.setNotOnOrAfter(c);
		} else
		{
			if (conditions.isSetNotOnOrAfter())
				conditions.unsetNotOnOrAfter();
		}
	}
	
	/**
	 * 
	 * @param value use negative value to remove proxy restriction 
	 */
	public void setProxyRestriction(int value)
	{
		ConditionsType conditions = getOrCreateConditions();
		if (value > 0)
		{
			if (conditions.sizeOfProxyRestrictionArray() == 0)
				conditions.addNewProxyRestriction();
			conditions.getProxyRestrictionArray(0).setCount(BigInteger.valueOf(value));
		} else
		{
			if (conditions.sizeOfProxyRestrictionArray() > 0)
				conditions.removeProxyRestriction(0);
		}
	}

	public void setAudienceRestriction(String []audienceArray)
	{
		ConditionsType conditions = getOrCreateConditions();
		if (audienceArray != null)
		{
			if (conditions.sizeOfAudienceRestrictionArray() == 0)
				conditions.addNewAudienceRestriction();
			conditions.getAudienceRestrictionArray(0).setAudienceArray(audienceArray);
		} else
		{
			if (conditions.sizeOfAudienceRestrictionArray() != 0)
				conditions.removeAudienceRestriction(0);
		}
	}

	
	public void addCustomCondition(XmlObject condition)
	{
		ConditionsType conditions = getOrCreateConditions();
		ConditionAbstractType newCondition = conditions.addNewCondition();
		newCondition.set(condition);
		XmlCursor cur = newCondition.newCursor();
		cur.toNextToken();
		QName type = condition.schemaType().getName();
		if (type == null)
			type = condition.schemaType().getDocumentElementName();
		String prefix = cur.prefixForNamespace(type.getNamespaceURI());
		cur.insertNamespace(prefix, type.getNamespaceURI());
		cur.insertAttributeWithValue("type", "http://www.w3.org/2001/XMLSchema-instance",  
				prefix + ":" + type.getLocalPart());
		cur.dispose();
	}
	
	public void sign(PrivateKey pk) throws DSigException 
	{
		sign(pk, null);
	}
	
	public void sign(PrivateKey pk, X509Certificate []cert) throws DSigException
	{
		DigSignatureUtil sign = new DigSignatureUtil();
		AssertionDocument unsignedDoc = getXMLBeanDoc();
		Document docToSign = SAMLUtils.getDOM(unsignedDoc);
		
		NodeList nodes = docToSign.getFirstChild().getChildNodes();
		Node sibling = null;
		for (int i=0; i<nodes.getLength(); i++)
		{
			Node n = nodes.item(i);
			if (n.getLocalName() != null) {
				if (n.getLocalName().equals("Subject")) {
					sibling = n;
					break;
				}
			}
		}

		sign.genEnvelopedSignature(pk, null, cert, 
				docToSign, sibling, SamlTrustChecker.ASSERTION_ID_QNAME);
		try
		{
			assertionDoc = AssertionDocument.Factory.parse(docToSign);
		} catch (XmlException e)
		{
			throw new DSigException("Parsing signed document failed", e);
		}
	}

	public void addAttribute(SAMLAttribute at)
	{
		addAttribute(at.getXBean());
	}
	
	public void addAttribute(AttributeType at)
	{
		if (assertionDoc.getAssertion().getAttributeStatementArray() == null ||
				assertionDoc.getAssertion().getAttributeStatementArray().length == 0)
			assertionDoc.getAssertion().addNewAttributeStatement();
		
		AttributeStatementType attrStatement = assertionDoc.getAssertion().getAttributeStatementArray(0);
		
		AttributeType added = attrStatement.addNewAttribute();
		added.set(at);
	}
	
	public void addAuthStatement(Calendar authTime, AuthnContextType ctx, 
			String sessionIdx, Calendar sessionEnd, 
			SubjectLocalityType subjectLocation)
	{
		if (assertionDoc.getAssertion().getAuthnStatementArray() == null || 
				assertionDoc.getAssertion().getAuthnStatementArray().length == 0)
			assertionDoc.getAssertion().addNewAuthnStatement();
		AuthnStatementType authStatement = assertionDoc.getAssertion().getAuthnStatementArray(0);
		authTime.setTimeZone(TimeZone.getTimeZone("UTC"));
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
}
