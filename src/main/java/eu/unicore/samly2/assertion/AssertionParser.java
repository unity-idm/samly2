/*
 * Copyright (c) 2007, 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on May 6, 2007
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.samly2.assertion;

import java.io.Serializable;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;

import org.w3c.dom.Document;

import eu.unicore.samly2.JAXBUtils;
import eu.unicore.samly2.SAMLConstants;
import eu.unicore.samly2.SAMLUtils;
import eu.unicore.samly2.exceptions.SAMLValidationException;
import eu.unicore.samly2.jaxb.saml2.assertion.AssertionType;
import eu.unicore.samly2.jaxb.saml2.assertion.ConditionAbstractType;
import eu.unicore.samly2.jaxb.saml2.assertion.Conditions;
import eu.unicore.samly2.jaxb.saml2.assertion.KeyInfoConfirmationDataType;
import eu.unicore.samly2.jaxb.saml2.assertion.NameIDType;
import eu.unicore.samly2.jaxb.saml2.assertion.ProxyRestrictionType;
import eu.unicore.samly2.jaxb.saml2.assertion.Subject;
import eu.unicore.samly2.jaxb.saml2.assertion.SubjectConfirmationData;
import eu.unicore.samly2.jaxb.saml2.assertion.SubjectConfirmationType;
import eu.unicore.samly2.jaxb.xmldsig.x2000.x09.KeyInfo;
import eu.unicore.samly2.jaxb.xmldsig.x2000.x09.KeyInfoType;
import eu.unicore.security.dsig.DSigException;
import eu.unicore.security.dsig.DigSignatureUtil;


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

	protected JAXBElement<AssertionType> assertionDoc;
	protected AssertionType assertion;
	
	protected AssertionParser()
	{
	}
	
	public AssertionParser(JAXBElement<AssertionType> doc)
	{
		assertionDoc = doc;
		assertion = assertionDoc.getValue();
	}

	/**
	 * Decrypts encrypted assertion and setups the object
	 * @param encryptedAssertion
	 * @param decryptKey
	 * @throws Exception
	 */
/*
	public AssertionParser(EncryptedAssertionDocument encryptedAssertion, PrivateKey decryptKey) throws Exception
	{
		EncryptionUtil encUtil = new EncryptionUtil();
		Document toDec = SAMLUtils.getDOM(encryptedAssertion);
		Document reverted = encUtil.decrypt(toDec, decryptKey);
		assertionDoc = AssertionDocument.Factory.parse(reverted.getDocumentElement().getFirstChild());
	}
*/	
	public String getIssuerName()
	{
		return assertion.getIssuer().getValue().getValue();
	}

	public String getSubjectName()
	{
		Optional<NameIDType> name = getSubjectNameID();
		return name.isPresent() ? null : name.get().getValue();
	}
	
	public String getIssuerNameFormat()
	{
		return assertion.getIssuer().getValue().getFormat();
	}

	public String getSubjectNameFormat()
	{
		Optional<NameIDType> name = getSubjectNameID();
		return name.isPresent() ? null : name.get().getFormat();
	}
	
	public Optional<NameIDType> getSubjectNameID()
	{
		List<JAXBElement<?>> content = assertion.getSubject().getValue().getBaseIDOrNameIDOrEncryptedID();
		return JAXBUtils.getFirstJAXB(content, NameIDType.class);
	}
	
	public boolean isSigned()
	{
		return assertion.getSignature() != null;
	}
	
	public void validateSignature(PublicKey key) throws SAMLValidationException
	{
		try
		{
			Document doc = getAsDOM();
			DigSignatureUtil sign = new DigSignatureUtil();
			if (!sign.verifyEnvelopedSignature(doc, Collections.singletonList(doc.getDocumentElement()),  
					SAMLConstants.ASSERTION_ID_QNAME, key))
				throw new SAMLValidationException("Signature is incorrect");
		} catch (JAXBException | DSigException e)
		{
			throw new SAMLValidationException("Signature verification failed", e);
		}
	}

	
	public Optional<X509Certificate[]> getIssuerFromSignature()
	{
		return SAMLUtils.getIssuerFromSignature(assertion.getSignature());
	}

	public Optional<X509Certificate[]> getSubjectFromConfirmation()
	{
		Subject subject = assertion.getSubject();
		if (subject == null)
			return Optional.empty();
		List<JAXBElement<?>> content = subject.getValue().getBaseIDOrNameIDOrEncryptedID();
		Optional<SubjectConfirmationType> confirmationO = 
				JAXBUtils.getFirstJAXB(content, SubjectConfirmationType.class);

		if (!confirmationO.isPresent())
			return Optional.empty();
		
		SubjectConfirmationType confirmation = confirmationO.get();
		SubjectConfirmationData subjectConfirmationData = confirmation.getSubjectConfirmationData();
		if (subjectConfirmationData == null)
			return Optional.empty();
		
		KeyInfoConfirmationDataType confirData;
		try
		{
			confirData = (KeyInfoConfirmationDataType)subjectConfirmationData.getValue();
		} catch (ClassCastException e)
		{
			return Optional.empty();
		}
		Optional<KeyInfo> kiO = JAXBUtils.getFirstObject(confirData.getContent(), KeyInfo.class);
		if (!kiO.isPresent())
			return Optional.empty();
		
		KeyInfoType ki = kiO.get().getValue();
		return SAMLUtils.extractCertificateFromKeyInfo(ki);
	}
	
	
	public JAXBElement<AssertionType> getJAXBObject()
	{
		return assertionDoc;
	}

	public Document getAsDOM() throws JAXBException
	{
		return SAMLUtils.getDOM(assertionDoc);
	}
	
	public int getProxyRestriction()
	{
		return getConditionByType(ProxyRestrictionType.class).
				map(pr -> pr.getCount().intValue()).
				orElse(-1);
	}
	
	private <T> Optional<T> getConditionByType(Class<T> type)
	{
		Conditions conditions = assertion.getConditions();
		if (conditions == null)
			return Optional.empty();
		List<JAXBElement<? extends ConditionAbstractType>> conditionsV = 
				conditions.getValue().getConditionOrAudienceRestrictionOrOneTimeUse();
		return JAXBUtils.getFirstJAXB(conditionsV, type);
	}
	
	public ZonedDateTime getNotBefore()
	{
		Conditions conditions = assertion.getConditions();
		if (conditions != null && conditions.getValue().getNotBefore() != null) {
			return conditions.getValue().getNotBefore().toGregorianCalendar().toZonedDateTime();
		}
		return null;
	}

	public ZonedDateTime getNotOnOrAfter()
	{
		Conditions conditions = assertion.getConditions();
		if (conditions != null && conditions.getValue().getNotOnOrAfter() != null) {
			return conditions.getValue().getNotOnOrAfter().toGregorianCalendar().toZonedDateTime();
		}
		return null;
	}
}
