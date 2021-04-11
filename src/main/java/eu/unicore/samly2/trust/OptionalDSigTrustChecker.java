/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.unicore.samly2.trust;

import eu.unicore.samly2.exceptions.SAMLValidationException;
import eu.unicore.samly2.messages.SAMLVerifiableElement;
import xmlbeans.org.oasis.saml2.assertion.NameIDType;
import xmlbeans.org.w3.x2000.x09.xmldsig.SignatureType;

/**
 * Extension of {@link DsigSamlTrustCheckerBase} which allows for optional signature mode. When activated
 * then trust checker is checking the signatures only if are present. If not present the signature is not checked
 * and assertion assumed as trusted. This latter mode is useful when trust is established outside of SAML protocol.
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
	protected void checkRequiredSignature(SAMLVerifiableElement message, NameIDType issuer, 
			SignatureType signature) throws SAMLValidationException
	{
		if (!message.isSigned())
		{
			if (!signatureOptional)
				throw new SAMLValidationException("SAML document is not signed and the policy requires a signature");
			else
				return;
		}
		checkSignature(message, issuer, signature);
	}
}