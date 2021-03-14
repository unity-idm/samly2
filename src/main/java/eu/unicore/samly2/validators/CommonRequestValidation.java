/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.unicore.samly2.validators;

import java.net.URI;
import java.net.URISyntaxException;

import eu.unicore.samly2.SAMLConstants;
import eu.unicore.samly2.SAMLUtils;
import eu.unicore.samly2.exceptions.SAMLRequesterException;
import eu.unicore.samly2.exceptions.SAMLServerException;
import eu.unicore.samly2.exceptions.SAMLValidationException;
import eu.unicore.samly2.exceptions.SAMLVersionException;
import xmlbeans.org.oasis.saml2.protocol.RequestAbstractType;

/**
 * Utility class with validation of SAML RequestAbstractType, which is the base of all SAML requests. 
 * The SAML 2.0 core specification rules are checked. This class is SAML profile/binding independent.
 * <p>
 * Besides of SAML spec rules this class implements also additional checks:
 * <ul>
 * <li> the request's issueInstant attribute is checked to fall in an allowed time frame, 
 * to detect outdated requests,
 * <li> replay checking is performed.
 * </ul> 
 * 
 * Impl note: this is a newer replacement of {@link AbstractRequestValidator} to be used as collaborator rather then 
 * super class.  
 */
public class CommonRequestValidation
{
	private URI responderEndpointUri;
	private long requestValidity;
	private ReplayAttackChecker replayChecker;

	public CommonRequestValidation(String responderEndpointUri, long requestValidity, ReplayAttackChecker replayChecker)
	{
		try
		{
			this.responderEndpointUri = SAMLUtils.normalizeUri(responderEndpointUri);
		} catch (URISyntaxException e)
		{
			throw new IllegalArgumentException("responderURI '" + responderEndpointUri + 
					"' is not a valid URI: " + e, e);
		}
		this.requestValidity = requestValidity;
		this.replayChecker = replayChecker;
	}
	
	public void validateBasicElements(RequestAbstractType request) throws SAMLServerException
	{
		checkMandatoryElements(request);
		validateDestination(request);
		validateAge(request);
	}

	public void validateReply(RequestAbstractType request) throws SAMLRequesterException
	{
		try
		{
			replayChecker.checkAndStore(request.getID(), requestValidity);
		} catch (SAMLValidationException e)
		{
			throw new SAMLRequesterException(SAMLConstants.SubStatus.STATUS2_REQUEST_DENIED, 
					e.getMessage());
		}
	}

	public void validateAge(RequestAbstractType request) throws SAMLRequesterException
	{
		long maxTs = request.getIssueInstant().getTimeInMillis() + requestValidity;
		if (maxTs < System.currentTimeMillis())
			throw new SAMLRequesterException(SAMLConstants.SubStatus.STATUS2_REQUEST_DENIED, 
					"Request is too old. It was issued at " + 
					request.getIssueInstant() + " and the validity timeframe is " + 
					requestValidity + "ms");
	}

	public void validateDestination(RequestAbstractType request) throws SAMLRequesterException
	{
		String destination = request.getDestination();
		if (destination != null)
		{
			URI destinationUri;
			try
			{
				destinationUri = SAMLUtils.normalizeUri(destination);
			} catch (URISyntaxException e)
			{
				throw new SAMLRequesterException(SAMLConstants.SubStatus.STATUS2_REQUEST_DENIED, "Destination value " + destination
						+ " is not a valid URI: " + e.toString());
			}
			
			if (!destinationUri.equals(responderEndpointUri))
				throw new SAMLRequesterException(SAMLConstants.SubStatus.STATUS2_REQUEST_DENIED, "Destination value " + destination
					+ " is not matching the responder's URI: " + responderEndpointUri);
		}
	}
	
	public void checkMandatoryElements(RequestAbstractType request) throws SAMLServerException
	{
		if (request.getID() == null || request.getID().equals(""))
			throw new SAMLRequesterException("Request must posses an ID");
		if (request.getVersion() == null || !request.getVersion().equals(SAMLConstants.SAML2_VERSION))
			throw new SAMLVersionException("Request must posses " + SAMLConstants.SAML2_VERSION + " version");
		if (request.getIssueInstant() == null)
			throw new SAMLRequesterException("Request must posses an IssueInstant");
	}
}
