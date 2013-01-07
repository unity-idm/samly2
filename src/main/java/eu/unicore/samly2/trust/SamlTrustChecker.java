/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.unicore.samly2.trust;

import org.apache.xmlbeans.XmlObject;

import eu.unicore.samly2.exceptions.SAMLValidationException;
import eu.unicore.security.dsig.IdAttribute;

import xmlbeans.org.oasis.saml2.assertion.AssertionDocument;
import xmlbeans.org.oasis.saml2.protocol.RequestAbstractType;
import xmlbeans.org.oasis.saml2.protocol.StatusResponseType;

/**
 * Performs checking whether consumer trusts the issuer of 
 * SAML assertion, request or response.
 * @author K. Benedyczak
 */
public interface SamlTrustChecker
{
	public static final IdAttribute PROTOCOL_ID_QNAME = new IdAttribute(null, "ID");
	public static final IdAttribute ASSERTION_ID_QNAME = new IdAttribute(null, "ID");

	public void checkTrust(AssertionDocument assertionDoc) throws SAMLValidationException;

	public void checkTrust(XmlObject responseDoc, StatusResponseType response) throws SAMLValidationException;

	public void checkTrust(XmlObject requestDoc, RequestAbstractType request) throws SAMLValidationException;
}
