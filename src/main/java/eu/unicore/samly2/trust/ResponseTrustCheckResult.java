/*
 * Copyright (c) 2015 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.samly2.trust;

/**
 * Stores response validation result. Typically it is not used directly by the validation code,
 * but only internally to pass response validation status to included assertion trust checking.
 * @author K. Benedyczak
 */
public class ResponseTrustCheckResult
{
	private boolean trustEstablished;

	public ResponseTrustCheckResult(boolean trustEstablished)
	{
		this.trustEstablished = trustEstablished;
	}

	/**
	 * @return true if the response trust was verified and it is trusted. If false then the response
	 * trust is undetermined. Note that this object is never used if the response is not trusted.
	 */
	public boolean isTrustEstablished()
	{
		return trustEstablished;
	}
}
