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
import eu.emi.security.authn.x509.impl.X500NameUtils;
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

	public void addTrustedDNIssuer(String entityDN, String endpointAddresses)
	{
		String dn = X500NameUtils.getComparableForm(entityDN);
		addTrustedIssuer(dn, endpointAddresses);
	}
	
	@Override
	public void checkTrust(AssertionDocument assertionDoc, ResponseTrustCheckResult rt) throws SAMLValidationException
	{
		throw new IllegalStateException("This trust checker should not be used for assertions validation");
	}

	@Override
	public ResponseTrustCheckResult checkTrust(XmlObject responseDoc, StatusResponseType response)
			throws SAMLValidationException
	{
		throw new IllegalStateException("This trust checker should not be used for responses validation");
	}

	@Override
	public void checkTrust(XmlObject requestDoc, RequestAbstractType request)
			throws SAMLValidationException
	{
		NameIDType issuer = request.getIssuer();
		String issuerName;
		try
		{
			if (issuer.getFormat() != null && issuer.getFormat().equals(SAMLConstants.NFORMAT_DN))
				issuerName = X500NameUtils.getComparableForm(issuer.getStringValue());
			else
				issuerName = issuer.getStringValue();
		} catch (Exception e)
		{
			throw new SAMLValidationException("The issuer name is misformatted", e);
		}

		Set<URI> addresses = trustedIssuers.get(issuerName);
		if (addresses == null)
			throw new SAMLValidationException("Issuer is not among trusted: " + issuer.getStringValue());
		
		if (request instanceof AuthnRequestType)
		{
			AuthnRequestType rr = (AuthnRequestType) request;
			String consumerUrl = rr.getAssertionConsumerServiceURL();
			if (consumerUrl != null)
				verifyConsumerServiceURL(consumerUrl, addresses);
		}
	}

	private void verifyConsumerServiceURL(String consumerUrl, Set<URI> addresses) 
			throws SAMLValidationException
	{
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
	
	@Override
	public void checkTrust(AssertionDocument assertionDoc) throws SAMLValidationException
	{
		checkTrust(assertionDoc, new ResponseTrustCheckResult(false));
	}

	/**
	 * Note: this method always throws exception as it shouldn't be used: signatures are not checked by
	 * this trust checker.
	 */
	@Override
	public CheckingMode getCheckingMode()
	{
		throw new IllegalStateException("Trust model of this validator is not using signatures");
	}
}
