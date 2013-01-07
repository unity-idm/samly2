/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.unicore.samly2.validators;

import java.util.Calendar;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;

import eu.unicore.samly2.exceptions.SAMLValidationException;

/**
 * Maintains stateful information about used identifiers of SAML assertions. 
 * Automatically removes outdated entries.
 * @author K. Benedyczak
 */
public class ReplayAttackChecker
{
	private Map<String, Long> usedIds = new HashMap<String, Long>();
	
	public synchronized void checkAndStore(String id, Calendar maxValidity) throws SAMLValidationException
	{
		checkAndStore(id, maxValidity.getTimeInMillis());
	}
	
	public synchronized void checkAndStore(String id, long maxValidity) throws SAMLValidationException
	{
		purgeOutdated();
		if (usedIds.containsKey(id))
			throw new SAMLValidationException("Replay attack detected. Reused SAML ID is: " + id);
		usedIds.put(id, maxValidity);
	}
	
	private void purgeOutdated()
	{
		long now = System.currentTimeMillis();
		Iterator<Entry<String, Long>> iterator = usedIds.entrySet().iterator();
		while (iterator.hasNext())
		{
			Entry<String, Long> entry = iterator.next();
			if (entry.getValue() < now)
				iterator.remove();
		}
	}
}
