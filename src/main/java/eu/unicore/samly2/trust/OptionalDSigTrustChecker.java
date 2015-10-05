/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.unicore.samly2.trust;

import org.apache.xmlbeans.XmlObject;

import xmlbeans.org.oasis.saml2.assertion.NameIDType;
import xmlbeans.org.w3.x2000.x09.xmldsig.SignatureType;
import eu.unicore.samly2.exceptions.SAMLValidationException;
import eu.unicore.security.dsig.IdAttribute;

/**
 * Extension of {@link DsigSamlTrustCheckerBase} which allows for optional signature mode. When activated
 * then trust checker is checking the signatures only if are present. If not present the signature is not checked
 * and assertion assumed as trusted. This latter mdoe is useful when trust is established outside of SAML protocol.
 * @author K. Benedyczak
 */
public abstract class OptionalDSigTrustChecker extends DsigSamlTrustCheckerBase
{
	private boolean signatureOptional;

	public OptionalDSigTrustChecker(CheckingMode checkingMode, boolean signatureOptional)
	{
		super(checkingMode);
		this.signatureOptional = signatureOptional;
	}
	
	@Override
	protected void checkRequiredSignature(XmlObject xmlbeansDoc, NameIDType issuer, 
			SignatureType signature, IdAttribute idAttribute) throws SAMLValidationException
	{
		if ((signature == null || signature.isNil()) && !signatureOptional)
			throw new SAMLValidationException("SAML document is not signed and the policy requires a signature");
		if ((signature == null || signature.isNil()))
			return;
		checkSignature(xmlbeansDoc, issuer, signature, idAttribute);
	}
}