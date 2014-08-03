/*
 * Copyright (c) 2007, 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on Sep 25, 2007
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.samly2;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Random;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.xmlbeans.XmlException;
import org.apache.xmlbeans.XmlObject;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import xmlbeans.org.oasis.saml2.assertion.AssertionDocument;
import xmlbeans.org.oasis.saml2.assertion.EncryptedAssertionDocument;
import xmlbeans.org.oasis.saml2.assertion.NameIDType;
import xmlbeans.org.oasis.saml2.protocol.ResponseType;
import xmlbeans.org.w3.x2000.x09.xmldsig.KeyInfoType;
import xmlbeans.org.w3.x2000.x09.xmldsig.SignatureType;
import xmlbeans.org.w3.x2000.x09.xmldsig.X509DataType;
import eu.unicore.samly2.assertion.AssertionParser;
import eu.unicore.security.dsig.DSigException;
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
	
	public static boolean compareNameIDs(NameIDType name1, NameIDType name2)
	{
		String format1 = name1.getFormat();
		if (format1 == null)
			format1 = SAMLConstants.NFORMAT_ENTITY;
		String format2 = name2.getFormat();
		if (format2 == null)
			format2 = SAMLConstants.NFORMAT_ENTITY;
		if (!format1.equals(format2))
			return false;
		
		if (name1.getStringValue() == null && name2.getStringValue() != null)
			return false;
		if (!name1.getStringValue().equals(name2.getStringValue()))
			return false;
		return true;
	}
	
	/**
	 * Extracts assertions from the wrapping SAML response in a safe way. It is guaranteed that no link is preserved 
	 * in the returned objects to the parameter object.
	 * @param response
	 * @return
	 * @throws XmlException
	 * @throws IOException
	 */
	public static AssertionDocument[] getAssertions(ResponseType response) 
		throws XmlException, IOException
	{
		
 		Element node = (Element)response.getDomNode();
 		NodeList allChildren = node.getChildNodes();
		NodeList asNodes = node.getElementsByTagNameNS(
			SAMLConstants.ASSERTION_NS, "Assertion");
		if (asNodes == null || asNodes.getLength() == 0)
			return new AssertionDocument[0];
		List<AssertionDocument> ret = new ArrayList<AssertionDocument>(asNodes.getLength());
		//work carefully: we only return Assertions which are direct children of the response,
		//to make XML Dsig attacks more difficult
		
		for (int i=0; i<asNodes.getLength(); i++)
		{
			Node asNode = asNodes.item(i);
			for (int j=0; j<allChildren.getLength(); j++)
			{
				if (allChildren.item(j).equals(asNode))
				{
					AssertionDocument wrapper = AssertionDocument.Factory.parse(asNode);
					//this weird... however without this step (slooow) the returned object is incorrectly 
					//handled in the signature checking code... 
					//though its XML text representation is fully correct even before this step.
					//TODO a better (faster) approach should be used.
					
					AssertionDocument wrapper2 = AssertionDocument.Factory.parse(wrapper.xmlText());
					ret.add(wrapper2);
				}
			}			
		}
		return ret.toArray(new AssertionDocument[ret.size()]);
	}
	
	/**
	 * Extracts encrypted assertions from the wrapping SAML response in a safe way. 
	 * It is guaranteed that no link is preserved in the returned objects to the parameter object.
	 * @param response
	 * @return
	 * @throws XmlException
	 * @throws IOException
	 */
	public static EncryptedAssertionDocument[] getEncryptedAssertions(ResponseType response) 
		throws XmlException, IOException
	{
		
 		Element node = (Element)response.getDomNode();
 		NodeList allChildren = node.getChildNodes();
		NodeList asNodes = node.getElementsByTagNameNS(
			SAMLConstants.ASSERTION_NS, "EncryptedAssertion");
		if (asNodes == null || asNodes.getLength() == 0)
			return new EncryptedAssertionDocument[0];
		List<EncryptedAssertionDocument> ret = new ArrayList<EncryptedAssertionDocument>(asNodes.getLength());
		for (int i=0; i<asNodes.getLength(); i++)
		{
			Node asNode = asNodes.item(i);
			for (int j=0; j<allChildren.getLength(); j++)
			{
				if (allChildren.item(j).equals(asNode))
				{
					EncryptedAssertionDocument parsed = EncryptedAssertionDocument.Factory.parse(asNode); 
					ret.add(parsed);
				}
			}			
		}
		return ret.toArray(new EncryptedAssertionDocument[ret.size()]);
	}
	
	/**
	 * Extracts all assertions from the response, decrypting those encrypted.
	 * @param response
	 * @param encryptionKey
	 * @return
	 * @throws Exception 
	 */
	public static List<AssertionDocument> extractAllAssertions(ResponseType response, PrivateKey decryptionKey) 
			throws Exception
	{
		
		AssertionDocument[] assertions = SAMLUtils.getAssertions(response);
		EncryptedAssertionDocument[] encAssertions = getEncryptedAssertions(response);
		List<AssertionDocument> allAs = new ArrayList<AssertionDocument>(assertions.length + 
				encAssertions.length);

		Collections.addAll(allAs, assertions);
		
		if (decryptionKey != null)
		{
			Collections.addAll(allAs, assertions);
			for (EncryptedAssertionDocument encAssertion: encAssertions)
			{
				AssertionParser parser = new AssertionParser(encAssertion, decryptionKey);
				//first we need to remove fragment
				AssertionDocument wrapper = parser.getXMLBeanDoc();
				AssertionDocument wrapper2 = AssertionDocument.Factory.newInstance(); 
				wrapper2.setAssertion(wrapper.getAssertion());
				
				//TODO same as above - extra rewrap needed for signatures
				AssertionDocument wrapper3 = AssertionDocument.Factory.parse(wrapper2.xmlText());
				
				allAs.add(wrapper3);
			}
		}
		return allAs;
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
