/*
 * Copyright (c) 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on Sep 25, 2008
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.security.dsig;

import java.io.IOException;
import java.io.StringWriter;

import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.w3c.dom.Document;
import org.w3c.dom.Node;


/**
 * Utility methods to simply dump XML DOM. Useful for logging
 * e.g. when exact XML must be outputted (without any 'pretty printing').
 */
public class DOMUtilities
{
	private static final Logger log = LogManager.getLogger("unicore.security.dsig." + 
			DOMUtilities.class.getSimpleName());
	
	public static String getDOMAsRawString(Document doc) throws IOException
	{
		return dumpNodeToString(doc);
	}

	public static void logDOMAsRawString(String prefix, Document doc, 
		Logger logger)
	{
		try
		{
			logger.trace(prefix + 
				getDOMAsRawString(doc));
		} catch (IOException e)
		{
			logger.warn("Can't serialize DOM to string: " + e);
		}
	}
	
	public static String dumpNodeToString(Node document)
	{
		TransformerFactory transformerFactory = TransformerFactory.newInstance();
		try
		{
			Transformer transformer = transformerFactory.newTransformer();
			StringWriter stringWriter = new StringWriter();
			StreamResult streamResult = new StreamResult(stringWriter);
			DOMSource domSource = new DOMSource(document);
			transformer.transform(domSource, streamResult);
			return stringWriter.toString();
		} catch (TransformerException e)
		{
        		log.warn("Can't serialize DOM Document to String: " + e);
        		return null;
		}
	}
}










