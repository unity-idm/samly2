/*
 * Copyright (c) 2016 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.samly2;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;

/**
 * JAXB helpers
 * @author K. Benedyczak
 */
public class JAXBUtils
{
	public static JAXBContext getContext() throws JAXBException
	{
		return JAXBContext.newInstance("eu.unicore.samly2.jaxb.saml2.assertion:"
				+ "eu.unicore.samly2.jaxb.saml2.protocol:"
				+ "eu.unicore.samly2.jaxb.xmldsig.x2000.x09:"
				+ "eu.unicore.samly2.jaxb.xmlenc.x2001.x04");	
	}
	
	/**
	 * @param content
	 * @param type
	 * @return the first occurrence of a value of the given type in the list
	 */
	@SuppressWarnings("unchecked")
	public static <T> Optional<T> getFirstJAXB(List<? extends JAXBElement<?>> content, Class<T> type)
	{
		if (content == null)
			return Optional.empty();
		return content.stream().
				filter(ce -> type.isAssignableFrom(ce.getValue().getClass())).
				findFirst().
				map(c -> (T)c);
	}

	/**
	 * @param content
	 * @param type
	 * @return the first occurrence of the given type in the list
	 */
	@SuppressWarnings("unchecked")
	public static <T> Optional<T> getFirstObject(List<?> content, Class<T> type)
	{
		if (content == null)
			return Optional.empty();
		return content.stream().
				filter(ce -> type.isAssignableFrom(ce.getClass())).
				findFirst().
				map(c -> (T)c);
	}
	
	/**
	 * 
	 * @param content
	 * @param type
	 * @return list with elements which are of the given type
	 */
	@SuppressWarnings("unchecked")
	public static <T> List<T> getObjects(List<?> content, Class<T> type)
	{
		if (content == null)
			return new ArrayList<>();
		return content.stream().
				filter(ce -> type.isAssignableFrom(ce.getClass())).
				map(c -> (T)c).
				collect(Collectors.toList());
	}
}
