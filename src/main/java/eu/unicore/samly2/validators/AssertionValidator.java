/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.unicore.samly2.validators;

import java.text.DateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import eu.emi.security.authn.x509.impl.X500NameUtils;
import eu.unicore.samly2.SAMLConstants;
import eu.unicore.samly2.exceptions.SAMLValidationException;
import eu.unicore.samly2.trust.ResponseTrustCheckResult;
import eu.unicore.samly2.trust.SamlTrustChecker;
import xmlbeans.org.oasis.saml2.assertion.AssertionDocument;
import xmlbeans.org.oasis.saml2.assertion.AssertionType;
import xmlbeans.org.oasis.saml2.assertion.AudienceRestrictionType;
import xmlbeans.org.oasis.saml2.assertion.ConditionsType;
import xmlbeans.org.oasis.saml2.assertion.SubjectConfirmationDataType;
import xmlbeans.org.oasis.saml2.assertion.SubjectConfirmationType;
import xmlbeans.org.oasis.saml2.assertion.SubjectType;

/**
 * Validates SAML assertion, checking only the SAML 2.0 core specification rules. This class
 * is SAML profile/binding independent. 
 * <p>
 * What is checked:
 * <ul>
 * <li> presence of required elements (ID, IssueInstant, Issuer, Subject)
 * <li> signature if required
 * <li> conditions if present
 * <li> subject's confirmation restrictions if present
 * </ul>
 * <p>
 * The following deviations from the SAML 2.0 core specification are implemented:
 * <ul>
 * <li> assertion MUST possess a subject. SAML allows for no subject in assertion but meaning
 * of such assertion is undefined. We don't support such assertions.
 * <li> if consumerSamlName or consumerEndpointUri parameters are null, then audienceRestriction
 * or subject's confirmation recipient (respectively) are not checked. This is against SAML specification.
 * <li> inResponseTo in subject confirmation is required when requestId is set (i.e. we are not checking an 
 * unsolicited response) and when the subject confirmation is bearer. This is a flexible interpretation of SAML
 * standard which is bit vague wrt inResponseToChecking, what is defined in various profiles, core spec etc. 
 * </ul>
 * <p>
 * This class allows for setting more then one allowed SAML consumer name.
 * 
 * @author K. Benedyczak
 */
public class AssertionValidator
{
	public static final long DEFAULT_VALIDITY_GRACE_PERIOD = 3*60000;
	private static final DateFormat DATE_FORMATTER = DateFormat.getDateTimeInstance(
			DateFormat.MEDIUM, DateFormat.MEDIUM);
	
	protected Set<String> consumerSamlNames;
	protected String consumerEndpointUri;
	protected String requestId;
	protected long samlValidityGraceTime;
	protected SamlTrustChecker trustChecker;
	protected ResponseTrustCheckResult responseCheckResult;

	public AssertionValidator(String consumerSamlName, String consumerEndpointUri, String requestId, 
			long samlValidityGraceTime, SamlTrustChecker trustChecker)
	{
		this(consumerSamlName, consumerEndpointUri, requestId, samlValidityGraceTime, trustChecker, 
				new ResponseTrustCheckResult(false));
	}
	
	public AssertionValidator(String consumerSamlName, String consumerEndpointUri, String requestId, 
			long samlValidityGraceTime, SamlTrustChecker trustChecker, 
			ResponseTrustCheckResult responseCheckResult)
	{
		this.responseCheckResult = responseCheckResult;
		this.consumerSamlNames = new HashSet<String>();
		if (consumerSamlName != null)
			this.consumerSamlNames.add(consumerSamlName);
		this.consumerEndpointUri = consumerEndpointUri;
		this.requestId = requestId;
		this.samlValidityGraceTime = samlValidityGraceTime;
		this.trustChecker = trustChecker;
	}
	
	public void addConsumerSamlNameAlias(String alias)
	{
		this.consumerSamlNames.add(alias);
	}
	
	public void validate(AssertionDocument assertionDoc) throws SAMLValidationException
	{
		AssertionType assertionXml = assertionDoc.getAssertion(); 
		checkMandatoryElements(assertionXml);
		trustChecker.checkTrust(assertionDoc, responseCheckResult);
		checkConditions(assertionXml);
		checkSubject(assertionXml);
	}

	protected void checkMandatoryElements(AssertionType assertion) throws SAMLValidationException
	{
		if (assertion.getID() == null || assertion.getID().equals(""))
			throw new SAMLValidationException("Assertion must posses an ID");
		if (assertion.getVersion() == null || !assertion.getVersion().equals(SAMLConstants.SAML2_VERSION))
			throw new SAMLValidationException("Assertion must posses " + SAMLConstants.SAML2_VERSION + " version");
		if (assertion.getIssueInstant() == null)
			throw new SAMLValidationException("Assertion must posses an IssueInstant");
		if (assertion.getIssuer() == null || assertion.getIssuer().isNil())
			throw new SAMLValidationException("Assertion must have its Issuer set");
		if (assertion.getIssuer().getStringValue() == null)
			throw new SAMLValidationException("Assertion must have its Issuer value set");
		if (assertion.getSubject() == null || assertion.getSubject().isNil())
			throw new SAMLValidationException("Assertion must have its Subject set");
		if (assertion.getSubject().getBaseID() != null && !assertion.getSubject().getBaseID().isNil())
			throw new SAMLValidationException("Assertions with custom subject IDs based on BaseID "
					+ "are not supported");
		if (assertion.getSubject().getEncryptedID() != null && !assertion.getSubject().getEncryptedID().isNil())
			throw new SAMLValidationException("Assertions with encrypted subject's nameID are not supported");
	}

	protected void checkSubject(AssertionType assertion) throws SAMLValidationException
	{
		SubjectType subject = assertion.getSubject();
		List<SubjectConfirmationType> confirmations = Stream.of(subject.getSubjectConfirmationArray())
				.filter(sc -> sc.getSubjectConfirmationData() != null).collect(Collectors.toList());
		if (confirmations == null || confirmations.size() == 0)
			return;

		ErrorReasons errors = new ErrorReasons();
		
		boolean foundValid = false;
		int i=1;
		for (SubjectConfirmationType confirmation: confirmations)
		{
			SubjectConfirmationDataType confData = confirmation.getSubjectConfirmationData();	
			if (confData.getRecipient() != null && consumerEndpointUri != null)
			{
				if (!confData.getRecipient().equals(consumerEndpointUri))
				{
					errors.addConfirmationError(i, "subject confirmation receipent URL " + 
							confData.getRecipient() + " is different from the expected one: " + consumerEndpointUri);
					continue;
				}
			}

			try
			{
				checkTimeBounds("Audience restriction", confData.getNotBefore(), confData.getNotOnOrAfter());
			} catch (SAMLValidationException e)
			{
				errors.addConfirmationError(i, e.getMessage());
				continue;
			}
			
			if (requestId != null)
			{
				if (!confData.isSetInResponseTo() && 
						SAMLConstants.CONFIRMATION_BEARER.equals(confirmation.getMethod()))
				{
					errors.addConfirmationError(i, "InResponseTo is not set for an assertion with " +
							"a bearer confirmation, and an expected requestId is " + requestId);
					continue;
				}
				if (confData.isSetInResponseTo() && !requestId.equals(confData.getInResponseTo()))
				{
					errors.addConfirmationError(i, "InResponseTo (" + confData.getInResponseTo() + 
						") is not equal to expected request id which was " + requestId);
					continue;
				}
			}
			foundValid = true;
			i++;
		}
		if (!foundValid)
			throw new SAMLValidationException("None of subject confirmations is valid: " + errors.toString());
	}
	
	protected void checkConditions(AssertionType assertion) throws SAMLValidationException
	{
		ConditionsType conditions = assertion.getConditions();
		if (conditions == null || conditions.isNil())
			return;

		if (conditions.getOneTimeUseArray() != null && conditions.getOneTimeUseArray().length > 1)
			throw new SAMLValidationException("Assertion may possess 0 or 1 OneTimeUse condition");
		if (conditions.getProxyRestrictionArray() != null && conditions.getProxyRestrictionArray().length > 1)
			throw new SAMLValidationException("Assertion may possess 0 or 1 ProxyRestriction condition");
		
		checkTimeBounds("Assertion", conditions.getNotBefore(), conditions.getNotOnOrAfter());
		checkAudienceRestriction(conditions.getAudienceRestrictionArray());
		checkGenericConditions(conditions);
	}
	
	protected void checkGenericConditions(ConditionsType conditions) throws SAMLValidationException
	{
		if (conditions.getConditionArray() != null && conditions.getConditionArray().length > 0)
			throw new SAMLValidationException("Got unsupported conditions in the assertion: " + 
					conditions.xmlText());
	}
	
	protected void checkAudienceRestriction(AudienceRestrictionType[] audienceRest) throws SAMLValidationException
	{
		if (audienceRest == null || audienceRest.length == 0 || consumerSamlNames.isEmpty())
			return;
		for (AudienceRestrictionType restriction: audienceRest)
		{
			String[] audiences = restriction.getAudienceArray();
			if (audiences == null)
				throw new SAMLValidationException("Assertion has wrong audience restriction: " +
						"no audiences defined inside");
			boolean found = false;
			for (String tested: audiences)
			{
				for (String allowed: consumerSamlNames)
					if (audienceMatching(allowed, tested))
					{
						found = true;
						break;
					}
				if (found)
					break;
			}
			if (!found)
				throw new SAMLValidationException("Assertion audience restriction doesn't include any of this service identifiers: "
						+ consumerSamlNames.toString() +" Audience is restricted to: " + restriction.xmlText());
		}
		
	}

	/**
	 * This is tricky: we can have DNs so equality test must be done properly, but we can URIs also...
	 */
	protected boolean audienceMatching(String audience, String tested)
	{
		if (audience.equals(tested))
			return true;
		try
		{
			if (X500NameUtils.equal(audience, tested))
				return true;
		} catch (Exception e)
		{
			//fine - not DNs
		}
		return false;
	}
	
	protected void checkTimeBounds(String msg, Calendar notBefore, Calendar notOnOrAfter) throws SAMLValidationException
	{
		long now = System.currentTimeMillis();
		if (notBefore != null && now < notBefore.getTimeInMillis()-samlValidityGraceTime)
			throw new SAMLValidationException(msg + " is not yet valid, will be from " 
				+ DATE_FORMATTER.format(notBefore.getTime()) + " and current time is " + DATE_FORMATTER.format(new Date()));
		if (notOnOrAfter != null && now >= notOnOrAfter.getTimeInMillis()+samlValidityGraceTime)
			throw new SAMLValidationException(msg + " expired at " 
				+ DATE_FORMATTER.format(notOnOrAfter.getTime()) + " and current time is " + DATE_FORMATTER.format(new Date()));
	}
}
