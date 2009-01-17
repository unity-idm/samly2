/*
 * Copyright (c) 2007, 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on Sep 25, 2007
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package pl.edu.icm.samly2;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Random;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.xmlbeans.XmlObject;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

import pl.edu.icm.samly2.dsig.DSigException;
import pl.edu.icm.samly2.dsig.Utils;
import xmlbeans.org.w3.www.x2000.x09.xmldsig.KeyInfoType;
import xmlbeans.org.w3.www.x2000.x09.xmldsig.SignatureType;
import xmlbeans.org.w3.www.x2000.x09.xmldsig.X509DataType;

/**
 * Auxiliary static SAML helpers.
 * @author K. Benedyczak
 */
public class SAMLUtils
{
	public static String genID(String prefix)
	{
		Random r = new Random(new Date().getTime());
		StringBuffer id = new StringBuffer(prefix);
		for (int i=0; i<3; i++)
			id.append(Long.toHexString(r.nextLong()));
		return id.toString();
	}
	
	public static X509Certificate[] getIssuerFromSignature(SignatureType signature)
	{
		if (signature == null)
			return null;
		KeyInfoType ki = signature.getKeyInfo();
		if (ki == null)
			return null;
		X509DataType[] x509Data = ki.getX509DataArray();
		if (x509Data == null)
			return null;
		for (int i=0; i<x509Data.length; i++)
			if (x509Data[i].getX509CertificateArray().length > 0)
				return Utils.deserializeCertificateChain(
						x509Data[i].getX509CertificateArray());
		return null;
	}
	
	public static Document getDOM(XmlObject xmlO) throws DSigException
	{
		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(true);
		Document docToSign;
		try
		{
			DocumentBuilder builder = dbf.newDocumentBuilder();
			docToSign = builder.parse(xmlO.newInputStream());
			return docToSign;
		} catch (ParserConfigurationException e)
		{
			throw new DSigException("Can't configure DOM parser", e);
		} catch (SAXException e)
		{
			throw new DSigException("DOM parse exception", e);
		} catch (IOException e)
		{
			throw new DSigException("IO Exception while parsing DOM ??", e);
		}
	}
}
