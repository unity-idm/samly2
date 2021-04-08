/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.unicore.samly2.trust;

import java.security.PublicKey;
import java.util.List;

import eu.unicore.samly2.exceptions.SAMLValidationException;
import eu.unicore.samly2.messages.SAMLVerifiableElement;
import eu.unicore.samly2.messages.XMLExpandedAssertion;
import xmlbeans.org.oasis.saml2.assertion.AssertionDocument;
import xmlbeans.org.oasis.saml2.assertion.AssertionType;
import xmlbeans.org.oasis.saml2.assertion.NameIDType;
import xmlbeans.org.oasis.saml2.protocol.RequestAbstractType;
import xmlbeans.org.oasis.saml2.protocol.StatusResponseType;
import xmlbeans.org.w3.x2000.x09.xmldsig.SignatureType;

/**
 * Configures and performs checking whether consumer trusts the issuer of 
 * SAML assertion, request or response.
 * <p>
 * The process is based on checking of the digital signature. 
 * Useful for extending.
 * @author K. Benedyczak
 */
public abstract class DsigSamlTrustCheckerBase implements SamlTrustChecker
{
	private CheckingMode mode;
	
	public DsigSamlTrustCheckerBase(CheckingMode mode)
	{
		this.mode = mode;
	}

	@Override
	public CheckingMode getCheckingMode()
	{
		return mode;
	}
	
	@Override
	public void checkTrust(AssertionDocument assertionDoc, ResponseTrustCheckResult responseCheckResult) 
			throws SAMLValidationException
	{
		AssertionType assertion = assertionDoc.getAssertion();
		XMLExpandedAssertion verifiableAssertion = new XMLExpandedAssertion(assertionDoc);
		if (mode == CheckingMode.REQUIRE_SIGNED_ASSERTION)
			checkRequiredSignature(verifiableAssertion, assertion.getIssuer(), assertion.getSignature());
		else
			checkOptionalSignature(verifiableAssertion, assertion.getIssuer(), assertion.getSignature());
	}

	@Override
	public void checkTrust(AssertionDocument assertionDoc) throws SAMLValidationException
	{
		checkTrust(assertionDoc, new ResponseTrustCheckResult(false));
	}
	
	@Override
	public ResponseTrustCheckResult checkTrust(SAMLVerifiableElement responseMessage, StatusResponseType response) 
			throws SAMLValidationException
	{
		SignatureType signature = response.getSignature();
		if (signature == null || signature.isNil())
			return new ResponseTrustCheckResult(false);
		
		checkSignature(responseMessage, response.getIssuer(), signature);
		return new ResponseTrustCheckResult(true);
	}

	@Override
	public void checkTrust(SAMLVerifiableElement requestMessage, RequestAbstractType request) throws SAMLValidationException
	{
		checkRequiredSignature(requestMessage, request.getIssuer(), request.getSignature());
	}

	protected void checkRequiredSignature(SAMLVerifiableElement message, NameIDType issuer, 
			SignatureType signature) throws SAMLValidationException
	{
		if (signature == null || signature.isNil())
			throw new SAMLValidationException("SAML document is not signed and the policy requires a signature");
		checkSignature(message, issuer, signature);
	}

	protected void checkOptionalSignature(SAMLVerifiableElement message, NameIDType issuer, 
			SignatureType signature) throws SAMLValidationException
	{
		if (signature == null || signature.isNil())
			return;
		checkSignature(message, issuer, signature);
	}
	
	protected void checkSignature(SAMLVerifiableElement message, NameIDType issuer, 
			SignatureType signature) throws SAMLValidationException
	{
		SignatureChecker dsigVerificator = 
				new SignatureChecker(nameId -> establishKey(nameId, signature));
		try
		{
			dsigVerificator.verify(issuer, message);
		} catch (SAMLTrustedKeyDiscoveryException e)
		{
			throw new SAMLValidationException(e.getMessage(), e);
		}
	}
	
	protected abstract List<PublicKey> establishKey(NameIDType issuer, SignatureType signature) throws SAMLTrustedKeyDiscoveryException;
	
	public class SAMLTrustedKeyDiscoveryException extends RuntimeException
	{
		public SAMLTrustedKeyDiscoveryException(String message)
		{
			super(message);
		}
	}
}
