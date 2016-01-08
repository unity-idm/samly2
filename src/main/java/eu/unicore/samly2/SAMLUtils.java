/*
 * Copyright (c) 2007, 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on Sep 25, 2007
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.samly2;

import java.net.URI;
import java.net.URISyntaxException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.Random;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.transform.dom.DOMResult;

import org.w3c.dom.Document;

import eu.unicore.samly2.jaxb.xmldsig.x2000.x09.KeyInfo;
import eu.unicore.samly2.jaxb.xmldsig.x2000.x09.KeyInfoType;
import eu.unicore.samly2.jaxb.xmldsig.x2000.x09.Signature;
import eu.unicore.samly2.jaxb.xmldsig.x2000.x09.X509Data;
import eu.unicore.security.dsig.Utils;

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
	
	public static Optional<X509Certificate[]> getIssuerFromSignature(Signature signature)
	{
		if (signature == null)
			return Optional.empty();
		KeyInfo ki = signature.getValue().getKeyInfo();
		if (ki == null)
			return Optional.empty();
		
		return extractCertificateFromKeyInfo(ki.getValue());
	}
	
	public static Optional<X509Certificate[]> extractCertificateFromKeyInfo(KeyInfoType ki)
	{
		List<X509Data> x509Data = JAXBUtils.getObjects(ki.getContent(), X509Data.class);
		if (x509Data.isEmpty())
			return Optional.empty();
		
		List<byte[]> encodedCerts = new ArrayList<>();
		for (X509Data x509Item: x509Data)
		{
			if ("X509Certificate".equals(x509Item.getName().getLocalPart()))
			{
				List<Object> certs = x509Item.getValue().getX509IssuerSerialOrX509SKIOrX509SubjectName();
				for (Object cert: certs)
				{
					if (cert instanceof JAXBElement)
					{
						JAXBElement<?> casted = (JAXBElement<?>) cert;
						encodedCerts.add((byte[]) casted.getValue());
					}
				}
			}
		}
		
		
		if (!encodedCerts.isEmpty())
			return Optional.of(Utils.deserializeCertificateChain(encodedCerts));
		return Optional.empty();
	}
	
	public static Document getDOM(JAXBElement<?> xmlO) throws JAXBException
	{
		JAXBContext jc = JAXBUtils.getContext();
		DOMResult res = new DOMResult();
		jc.createMarshaller().marshal(xmlO, res);
		return (Document)res.getNode();
	}
		
	public static URI normalizeUri(String uri) throws URISyntaxException
	{
		URI destinationUri = new URI(uri);
		if ((destinationUri.getPort() == 443 && "https".equals(destinationUri.getScheme())) ||
				(destinationUri.getPort() == 80 && "http".equals(destinationUri.getScheme())))
			return new URI(destinationUri.getScheme(), destinationUri.getUserInfo(), 
					destinationUri.getHost(), -1, destinationUri.getPath(), 
					destinationUri.getQuery(), destinationUri.getFragment());
		return destinationUri;
	}
}
