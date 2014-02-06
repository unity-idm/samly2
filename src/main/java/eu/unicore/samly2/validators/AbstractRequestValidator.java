/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.unicore.samly2.validators;

import java.net.URI;
import java.net.URISyntaxException;

import org.apache.xmlbeans.XmlObject;

import eu.unicore.samly2.SAMLConstants;
import eu.unicore.samly2.exceptions.SAMLRequesterException;
import eu.unicore.samly2.exceptions.SAMLServerException;
import eu.unicore.samly2.exceptions.SAMLValidationException;
import eu.unicore.samly2.exceptions.SAMLVersionException;
import eu.unicore.samly2.trust.SamlTrustChecker;

import xmlbeans.org.oasis.saml2.protocol.RequestAbstractType;

/**
 * Validates SAML RequestAbstractType, which is the base of all SAML requests. 
 * The SAML 2.0 core specification rules are checked. This class
 * is SAML profile/binding independent.
 * Signature is checked always when present, but its presence is not enforced.
 * <p>
 * Besides of SAML spec rules this class implements also additional checks:
 * <ul>
 * <li> the request's issueInstant attribute is checked to fall in an allowed time frame, 
 * to detect outdated requests,
 * <li> replay checking is performed.
 * </ul> 
 * 
 * @author K. Benedyczak
 */
public class AbstractRequestValidator
{
	protected URI responderEndpointUri;
	protected SamlTrustChecker trustChecker;
	protected long requestValidity;
	protected ReplayAttackChecker replayChecker;

	public AbstractRequestValidator(String responderEndpointUri, SamlTrustChecker trustChecker,
			long requestValidity, ReplayAttackChecker replayChecker)
	{
		try
		{
			this.responderEndpointUri = normalizeUri(responderEndpointUri);
		} catch (URISyntaxException e)
		{
			throw new IllegalArgumentException("responderURI '" + responderEndpointUri + 
					"' is not a valid URI: " + e, e);
		}
		this.trustChecker = trustChecker;
		this.requestValidity = requestValidity;
		this.replayChecker = replayChecker;
	}
	
	public void validate(XmlObject wrappingDcoument, RequestAbstractType request) throws SAMLServerException
	{
		checkMandatoryElements(request);
		
		
		String destination = request.getDestination();
		if (destination != null)
		{
			URI destinationUri;
			try
			{
				destinationUri = normalizeUri(destination);
			} catch (URISyntaxException e)
			{
				throw new SAMLRequesterException(SAMLConstants.SubStatus.STATUS2_REQUEST_DENIED, "Destination value " + destination
						+ " is not a valid URI: " + e.toString());
			}
			
			if (!destinationUri.equals(responderEndpointUri))
				throw new SAMLRequesterException(SAMLConstants.SubStatus.STATUS2_REQUEST_DENIED, "Destination value " + destination
					+ " is not matching the responder's URI: " + responderEndpointUri);
		}
		if (request.getSignature() != null && !request.getSignature().isNil())
		{
			try
			{
				trustChecker.checkTrust(wrappingDcoument, request);
			} catch (SAMLValidationException e)
			{
				throw new SAMLRequesterException(SAMLConstants.SubStatus.STATUS2_REQUEST_DENIED,
						e.getMessage(), e.getCause());
			}
		}
		
		long maxTs = request.getIssueInstant().getTimeInMillis() + requestValidity;
		if (maxTs < System.currentTimeMillis())
			throw new SAMLRequesterException(SAMLConstants.SubStatus.STATUS2_REQUEST_DENIED, 
					"Request is too old. It was issued at " + 
					request.getIssueInstant() + " and the validity timeframe is " + 
					requestValidity + "ms");
		
		try
		{
			replayChecker.checkAndStore(request.getID(), requestValidity);
		} catch (SAMLValidationException e)
		{
			throw new SAMLRequesterException(SAMLConstants.SubStatus.STATUS2_REQUEST_DENIED, 
					e.getMessage());
		}
	}
	
	private URI normalizeUri(String uri) throws URISyntaxException
	{
		URI destinationUri = new URI(uri);
		if ((destinationUri.getPort() == 443 && "https".equals(destinationUri.getScheme())) ||
				(destinationUri.getPort() == 80 && "http".equals(destinationUri.getScheme())))
			return new URI(destinationUri.getScheme(), destinationUri.getUserInfo(), 
					destinationUri.getHost(), -1, destinationUri.getPath(), 
					destinationUri.getQuery(), destinationUri.getFragment());
		return destinationUri;
	}
	
	protected void checkMandatoryElements(RequestAbstractType request) throws SAMLServerException
	{
		if (request.getID() == null || request.getID().equals(""))
			throw new SAMLRequesterException("Request must posses an ID");
		if (request.getVersion() == null || !request.getVersion().equals(SAMLConstants.SAML2_VERSION))
			throw new SAMLVersionException("Request must posses " + SAMLConstants.SAML2_VERSION + " version");
		if (request.getIssueInstant() == null)
			throw new SAMLRequesterException("Request must posses an IssueInstant");
	}
}
