/*
 * Copyright (c) 2007, 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on May 6, 2007
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package pl.edu.icm.samly2.assertion;

import java.io.IOException;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;

import javax.xml.namespace.QName;

import org.apache.xml.security.utils.RFC2253Parser;
import org.apache.xmlbeans.XmlCursor;
import org.apache.xmlbeans.XmlException;
import org.apache.xmlbeans.XmlObject;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import pl.edu.icm.samly2.SAMLConstants;
import pl.edu.icm.samly2.SAMLUtils;
import pl.edu.icm.samly2.dsig.DSigException;
import pl.edu.icm.samly2.dsig.DigSignatureUtil;
import pl.edu.icm.samly2.dsig.Utils;
import pl.edu.icm.samly2.exceptions.SAMLParseException;

import xmlbeans.org.oasis.saml2.assertion.AssertionDocument;
import xmlbeans.org.oasis.saml2.assertion.AssertionType;
import xmlbeans.org.oasis.saml2.assertion.AudienceRestrictionType;
import xmlbeans.org.oasis.saml2.assertion.ConditionAbstractType;
import xmlbeans.org.oasis.saml2.assertion.ConditionsType;
import xmlbeans.org.oasis.saml2.assertion.KeyInfoConfirmationDataType;
import xmlbeans.org.oasis.saml2.assertion.NameIDType;
import xmlbeans.org.oasis.saml2.assertion.ProxyRestrictionType;
import xmlbeans.org.oasis.saml2.assertion.SubjectConfirmationType;
import xmlbeans.org.oasis.saml2.assertion.SubjectType;
import xmlbeans.org.w3.x2000.x09.xmldsig.KeyInfoType;
import xmlbeans.org.w3.x2000.x09.xmldsig.X509DataType;


/**
 * SAML v2 assertion. It is generic, i.e. can represent any kind of assertion 
 * (identity, attribute, ...) but implements only subset of SAML constructs.
 * There is no code related to statements here.
 * 
 * @author K. Benedyczak
 */
public abstract class AbstractAssertion
{
	private static String ID_PREFIX = "SAMLY2lib_assert_";
	
	protected AssertionType assertion;
	private AssertionDocument assertionDoc;
	private ConditionsType conditions;
	private ProxyRestrictionType proxyRestriction;
	private AudienceRestrictionType audienceRestriction;
	private boolean modified;
	private int conditionsCount;
	
	private String issuerDN, subjectDN;
	
	public AbstractAssertion()
	{
		modified = true;
		proxyRestriction = null;
		audienceRestriction = null;
		conditionsCount = 0;
		
		assertionDoc = AssertionDocument.Factory.newInstance();

		assertion = AssertionType.Factory.newInstance();
		assertion.setVersion(SAMLConstants.SAML2_VERSION);
		assertion.setIssueInstant(Calendar.getInstance());
		assertion.setID(SAMLUtils.genID(ID_PREFIX));

		conditions = ConditionsType.Factory.newInstance();
	}
	
	public AbstractAssertion(AssertionDocument doc) throws SAMLParseException, 
		XmlException, IOException
	{
		modified = true;
		assertionDoc = AssertionDocument.Factory.parse(
				doc.newReader());
		assertion = assertionDoc.getAssertion();
		if (assertion == null)
			assertion = AssertionType.Factory.newInstance();
		conditions = assertion.getConditions();
		proxyRestriction = null;
		audienceRestriction = null;
		if (conditions != null)
		{
			ProxyRestrictionType pp[] = conditions.getProxyRestrictionArray();
			if (pp.length > 0)
				proxyRestriction = pp[0];
			AudienceRestrictionType ar[] = conditions.getAudienceRestrictionArray();
			if (ar.length > 0)
				audienceRestriction = ar[0];
		} else
			conditions = ConditionsType.Factory.newInstance();

		NameIDType n1 =  assertion.getIssuer();
		if (n1 != null)
		{
			if (SAMLConstants.NFORMAT_DN.equals(n1.getFormat()))
			{
				XmlCursor cur = n1.newCursor();
				cur.toFirstContentToken();
				issuerDN = cur.getTextValue();
			} /*else
				throw new SAMLParseException("Unsupported " +
					"issuer format: " + n1.getFormat());*/
		} else
			throw new SAMLParseException("No issuer in assertion");
		
		SubjectType s =  assertion.getSubject();
		if (s != null && s.getNameID() != null)
		{
			n1 = s.getNameID();
			if (SAMLConstants.NFORMAT_DN.equals(n1.getFormat()))
			{
				XmlCursor cur = n1.newCursor();
				cur.toFirstContentToken();
				subjectDN = cur.getTextValue();
			} /*else
				throw new SAMLParseException("Unsupported " +
					"subject format: " + n1.getFormat());*/			
		}
	}

	public void setX509Issuer(String issuerName)
	{
		String dn = RFC2253Parser.rfc2253toXMLdsig(issuerName);
		NameIDType issuerN = NameIDType.Factory.newInstance();
		issuerN.setFormat(SAMLConstants.NFORMAT_DN);
		issuerN.setStringValue(dn);
		assertion.setIssuer(issuerN);
		issuerDN = dn;
		modified = true;
	}

	public void setIssuer(NameIDType issuer)
	{
		assertion.setIssuer(issuer);
		if (issuer.getFormat().equals(SAMLConstants.NFORMAT_DN))
			issuerDN = issuer.getStringValue();
		modified = true;
	}
	
	public void setX509Subject(String subjectName)
	{
		String dn = RFC2253Parser.rfc2253toXMLdsig(subjectName);
		NameIDType subjectN = NameIDType.Factory.newInstance();
		subjectN.setFormat(SAMLConstants.NFORMAT_DN);
		subjectN.setStringValue(dn);

		SubjectType subjectT = SubjectType.Factory.newInstance();
		subjectT.setNameID(subjectN);
		assertion.setSubject(subjectT);
		subjectDN = dn;
		modified = true;
	}

	public void setSubject(NameIDType subject)
	{
		SubjectType subjectT = SubjectType.Factory.newInstance();
		subjectT.setNameID(subject);
		assertion.setSubject(subjectT);
		if (subject.getFormat().equals(SAMLConstants.NFORMAT_DN))
			subjectDN = subject.getStringValue();
		modified = true;
	}

	public void setSubject(SubjectType subject)
	{
		assertion.setSubject(subject);
		if (subject.getNameID().getFormat().equals(SAMLConstants.NFORMAT_DN))
			subjectDN = subject.getNameID().getStringValue();
		modified = true;
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
		SubjectType subject = assertion.getSubject();
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
		assertion.setIssueInstant(Calendar.getInstance());		
	}

	public void setTimeConditions(Date notBefore, Date notOnOrAfter)
	{
		Calendar c = Calendar.getInstance();
		if (notBefore != null)
		{
			if (!conditions.isSetNotBefore())
				conditionsCount++;
			c.setTime(notBefore);
			conditions.setNotBefore(c);
		} else
		{
			if (conditions.isSetNotBefore())
			{
				conditionsCount--;
				conditions.unsetNotBefore();
			}
		}
		if (notOnOrAfter != null)
		{
			if (!conditions.isSetNotOnOrAfter())
				conditionsCount++;
			c.setTime(notOnOrAfter);
			conditions.setNotOnOrAfter(c);
			conditionsCount++;
		} else
		{
			if (conditions.isSetNotOnOrAfter())
			{
				conditionsCount--;
				conditions.unsetNotOnOrAfter();
			}
		}
		
		modified = true;
	}
	
	/**
	 * Checks if time is in this assertion's lifetime. If the assertion doesn't
	 * have lifetime set then true is returned.   
	 * @param time
	 * @return
	 */
	public boolean checkTimeConditions(Date time)
	{
		long t = time.getTime();
		if (getNotBefore() != null && getNotBefore().getTime() > t)
			return false;
		if (getNotOnOrAfter() != null && getNotOnOrAfter().getTime() <= t)
			return false;
		return true;
	}

	/**
	 * Checks if current time is in this assertion's lifetime. If the assertion doesn't
	 * have lifetime set then true is returned.   
	 * @param time
	 * @return
	 */
	public boolean checkTimeConditions()
	{
		return checkTimeConditions(new Date());
	}

	/**
	 * 
	 * @param value use negative value to remove proxy restriction 
	 */
	public void setProxyRestriction(int value)
	{
		if (value > 0)
		{
			if (proxyRestriction == null)
			{
				proxyRestriction = conditions.addNewProxyRestriction();
				conditionsCount++;
			}
			proxyRestriction.setCount(BigInteger.valueOf(value));
		} else
		{
			if (proxyRestriction != null)
			{
				conditions.removeProxyRestriction(0);
				proxyRestriction = null;
				conditionsCount--;
			}
		}
		modified = true;
	}

	public void setAudienceRestriction(String []audienceArray)
	{
		if (audienceArray != null)
		{
			if (audienceRestriction == null)
			{
				audienceRestriction = conditions.addNewAudienceRestriction();
				conditionsCount++;
			}
			audienceRestriction.setAudienceArray(audienceArray);
		} else
		{
			if (audienceRestriction != null)
			{
				conditions.removeAudienceRestriction(0);
				audienceRestriction = null;
				conditionsCount--;
			}
		}
		modified = true;
	}

	
	public void addCustomCondition(XmlObject condition)
	{
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
		conditionsCount++;
		modified = true;
	}
	
	public void sign(PrivateKey pk) throws DSigException 
	{
		sign(pk, null);
	}
	
	public void sign(PrivateKey pk, X509Certificate []cert) throws DSigException
	{
		DigSignatureUtil sign = new DigSignatureUtil();
		AssertionDocument unsignedDoc = getXML();
		Document docToSign = SAMLUtils.getDOM(unsignedDoc);
		
		NodeList nodes = docToSign.getFirstChild().getChildNodes();
		Node sibling = null;
		for (int i=0; i<nodes.getLength(); i++)
		{
			Node n = nodes.item(i);
			if (n.getLocalName().equals("Subject"))
			{
				sibling = n;
				break;
			}
		}

		sign.genEnvelopedSignature(pk, null, cert, 
				docToSign, sibling);
		try
		{
			assertionDoc = AssertionDocument.Factory.parse(docToSign);
		} catch (XmlException e)
		{
			throw new DSigException("Parsing signed document failed", e);
		}
		assertion = assertionDoc.getAssertion();
	}

	public boolean isSigned()
	{
		if (assertionDoc.getAssertion().getSignature() == null 
				|| assertionDoc.getAssertion().getSignature().isNil())
			return false;
		else return true;
	}
	
	public boolean isCorrectlySigned(PublicKey key) throws DSigException
	{
		if (!isSigned())
			return false;
		DigSignatureUtil sign = new DigSignatureUtil();
		return sign.verifyEnvelopedSignature(
			(Document) getXML().getDomNode(), key);
	}
	
	public X509Certificate[] getIssuerFromSignature()
	{
		return SAMLUtils.getIssuerFromSignature(assertion.getSignature());
	}

	public X509Certificate[] getSubjectFromConfirmation()
	{
		SubjectType subject = assertion.getSubject();
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
	
	
	public AssertionDocument getXML()
	{
		if (modified)
		{
			if (conditionsCount > 0)
				assertion.setConditions(conditions);
			assertionDoc.setAssertion(assertion);
			modified = false;
		}
		return assertionDoc;
	}
	
	public String getIssuerDN()
	{
		return issuerDN;
	}
	
	public String getSubjectDN()
	{
		return subjectDN;
	}
	
	public int getProxyRestriction()
	{
		if (proxyRestriction == null)
			return -1;
		return proxyRestriction.getCount().intValue();
	}
	
	public Date getNotBefore()
	{
		Calendar c = conditions.getNotBefore();
		return c == null ? null : c.getTime();
	}

	public Date getNotOnOrAfter()
	{
		Calendar c = conditions.getNotOnOrAfter();
		return c == null ? null : c.getTime();
	}
	
	public ConditionAbstractType[] getCustomConditions()
	{
		return conditions.getConditionArray();
	}
}
