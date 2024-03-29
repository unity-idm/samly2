/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.unicore.samly2.validators;

import eu.unicore.samly2.SAMLConstants;
import eu.unicore.samly2.exceptions.SAMLErrorResponseException;
import eu.unicore.samly2.exceptions.SAMLValidationException;
import xmlbeans.org.oasis.saml2.protocol.StatusCodeType;
import xmlbeans.org.oasis.saml2.protocol.StatusResponseType;
import xmlbeans.org.oasis.saml2.protocol.StatusType;

/**
 * Validates SAML StatusResponse, checking only the SAML 2.0 core specification rules. This class
 * is SAML profile/binding independent. It is useful for basic response checking in all SAML protocols
 * as all responses extend the StatusResponseType.
 * <p>
 * Note: this class allows to pass null consumerEndpointUri. If so, then the response destination
 * is not checked, what is against SAML specification.
 */
public class CommonResponseValidator
{
	private final String consumerEndpointUri;
	private final String requestId;

	public CommonResponseValidator(String consumerEndpointUri, String requestId)
	{
		this.consumerEndpointUri = consumerEndpointUri;
		this.requestId = requestId;
	}
	
	public void validate(StatusResponseType responseXml) throws SAMLValidationException
	{
		checkMandatoryElements(responseXml);
		
		validateResponseTo(responseXml);

		validateDestination(responseXml);

		checkStatus(responseXml);
	}

	private void validateResponseTo(StatusResponseType responseXml) throws SAMLValidationException
	{
		String inResponseTo = responseXml.getInResponseTo(); 
		if (requestId != null && inResponseTo != null && !inResponseTo.equals(requestId))
			throw new SAMLValidationException("InResponseTo value " + inResponseTo
					+ " is not matching expected requestId: " + requestId);
	}

	private void validateDestination(StatusResponseType responseXml) throws SAMLValidationException
	{
		String destination = responseXml.getDestination();
		if (destination != null && consumerEndpointUri != null &&
				!destination.equals(consumerEndpointUri))
			throw new SAMLValidationException("Destination value " + destination
					+ " is not matching consumer URI: " + consumerEndpointUri);
	}
	
	private void checkMandatoryElements(StatusResponseType responseXml) throws SAMLValidationException
	{
		if (responseXml.getID() == null || responseXml.getID().equals(""))
			throw new SAMLValidationException("Response must posses an ID");
		if (responseXml.getVersion() == null || !responseXml.getVersion().equals(SAMLConstants.SAML2_VERSION))
			throw new SAMLValidationException("Response must posses " + SAMLConstants.SAML2_VERSION + " version");
		if (responseXml.getIssueInstant() == null)
			throw new SAMLValidationException("Response must posses an IssueInstant");
		if (responseXml.getStatus() == null || responseXml.getStatus().isNil())
			throw new SAMLValidationException("Response must have a status set");
	}

	private void checkStatus(StatusResponseType responseXml) throws SAMLValidationException
	{
		StatusType status = responseXml.getStatus();
		if (status.getStatusCode() == null || status.getStatusCode().isNil())
			throw new SAMLValidationException("Response must have status code set");
		String statusValue = status.getStatusCode().getValue();
		if (statusValue == null)
			throw new SAMLValidationException("Response must have status code's value set");
		if (statusValue.equals(SAMLConstants.Status.STATUS_OK.toString()))
			return;
		if (!(statusValue.equals(SAMLConstants.Status.STATUS_REQUESTER.toString()) || 
				statusValue.equals(SAMLConstants.Status.STATUS_RESPONDER.toString()) ||
				statusValue.equals(SAMLConstants.Status.STATUS_VERSION_MISMATCH.toString())))
			throw new SAMLValidationException("Response has illegal status value: " + statusValue);
		StringBuilder msg = new StringBuilder();
		msg.append("Got error in the response. Caused by ");
		msg.append(statusValue.substring(statusValue.lastIndexOf(":")+1));
		StatusCodeType subCode = status.getStatusCode().getStatusCode(); 
		if (subCode != null && subCode.getValue() != null)
		{
			String value = subCode.getValue();
			if (value.startsWith(SAMLConstants.STAT_P))
				value = value.substring(SAMLConstants.STAT_P.length());
			msg.append(" Error type: " + value);
		}
		if (status.getStatusMessage() != null)
			msg.append(" Message: " + status.getStatusMessage());
		if (subCode != null && subCode.getValue() != null)
			throw new SAMLErrorResponseException(SAMLConstants.Status.fromString(statusValue), 
				SAMLConstants.SubStatus.fromString(subCode.getValue()), msg.toString());
		else
			throw new SAMLErrorResponseException(SAMLConstants.Status.fromString(statusValue), 
					msg.toString());
	}	
	
}
