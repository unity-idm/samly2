/*
 * Copyright (c) 2014 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.samly2.trust;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.apache.xmlbeans.XmlObject;

import xmlbeans.org.oasis.saml2.assertion.AssertionDocument;
import xmlbeans.org.oasis.saml2.assertion.NameIDType;
import xmlbeans.org.oasis.saml2.protocol.AuthnRequestType;
import xmlbeans.org.oasis.saml2.protocol.RequestAbstractType;
import xmlbeans.org.oasis.saml2.protocol.StatusResponseType;
import eu.unicore.samly2.SAMLConstants;
import eu.unicore.samly2.SAMLUtils;
import eu.unicore.samly2.exceptions.SAMLValidationException;

/**
 * Metadata based trust checker: signatures are not required, however issuers must be 
 * among a list of trusted ones. What is more if a return is set in the request it must match the
 * configured address.
 * <p>
 * Important: this trust checker should not be used on a response consumer end, it is working for requests 
 * with assumption that a response is sent to a well known address.
 *  
 * @author K. Benedyczak
 */
public class EnumeratedTrustChecker implements SamlTrustChecker
{
	protected Map<String, Set<URI>> trustedIssuers = new HashMap<String, Set<URI>>();
	
	public void addTrustedIssuer(String entityId, String endpointAddresses)
	{
		Set<URI> current = trustedIssuers.get(entityId);
		if (current == null)
		{
			current = new HashSet<URI>();
			trustedIssuers.put(entityId, current);
		}
		try
		{
			current.add(SAMLUtils.normalizeUri(endpointAddresses));
		} catch (URISyntaxException e)
		{
			throw new IllegalArgumentException("Provided address is not a valid URI", e);
		}
	}
	
	@Override
	public void checkTrust(AssertionDocument assertionDoc) throws SAMLValidationException
	{
		throw new IllegalStateException("This trust checker should not be used for assertions validation");
	}

	@Override
	public void checkTrust(XmlObject responseDoc, StatusResponseType response)
			throws SAMLValidationException
	{
		throw new IllegalStateException("This trust checker should not be used for responses validation");
	}

	@Override
	public void checkTrust(XmlObject requestDoc, RequestAbstractType request)
			throws SAMLValidationException
	{
		NameIDType issuer = request.getIssuer();
		if (issuer.getFormat() != null && !issuer.getFormat().equals(SAMLConstants.NFORMAT_ENTITY))
			throw new SAMLValidationException("Issuer name must be of " + SAMLConstants.NFORMAT_ENTITY +
					" format");
		Set<URI> addresses = trustedIssuers.get(issuer.getStringValue());
		if (addresses == null)
			throw new SAMLValidationException("Issuer is not among trusted: " + issuer.getStringValue());
		
		if (request instanceof AuthnRequestType)
		{
			AuthnRequestType rr = (AuthnRequestType) request;
			String consumerUrl = rr.getAssertionConsumerServiceURL();
			try
			{
				URI consumerUri = SAMLUtils.normalizeUri(consumerUrl);
				if (!addresses.contains(consumerUri))
					throw new SAMLValidationException("AssertionConsumerServiceURL in request (" 
							+ consumerUrl + ") is not among trusted endpoints of the " +
									"issuer.");
			} catch (URISyntaxException e)
			{
				throw new SAMLValidationException("AssertionConsumerServiceURL is not a valid URI: "
						+ consumerUrl, e);
			}
		}
	}

	@Override
	public boolean isSignatureRequired()
	{
		return false;
	}
}
