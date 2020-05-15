/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.unicore.security.dsig;

/**
 * Optional namespace and local name of attribute
 * @author K. Benedyczak
 */
public class IdAttribute
{
	private final String namespace;
	private final String localName;

	/**
	 * @param namespace can be null
	 */
	public IdAttribute(String namespace, String localName)
	{
		this.namespace = namespace;
		this.localName = localName;
	}

	public String getNamespace()
	{
		return namespace;
	}

	public String getLocalName()
	{
		return localName;
	}
}
