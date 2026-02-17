/*
 * Copyright (c) 2007, 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on Apr 24, 2007
 */

package eu.unicore.security.dsig;

import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.Security;
import java.util.Base64;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dom.DOMCryptoContext;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;

import org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;


public class DigSignatureVerificator
{
	private static final Logger log = LogManager.getLogger("unicore.security.dsig." + 
		DigSignatureVerificator.class.getSimpleName());
	private XMLSignatureFactory fac = null;
	
	public DigSignatureVerificator() throws DSigException
	{
		try
		{
			Security.addProvider(new XMLDSigRI());
			fac = XMLSignatureFactory.getInstance("DOM", "ApacheXMLDSig");
		} catch (Exception e)
		{
			throw new DSigException("Initialization of digital signature engine failed", e);
		}
	}
	
	/**
	 * @param signedDocument document which contains signed data (not necessary the whole document 
	 * need to be signed). 
	 * @param shallBeSigned list of elements in the document which should be signed.
	 * @param idAttribute what attribute holds information about element's identifier, which 
	 * @param validatingKey key which shall be used for signature verification
	 * @return true only if signature is valid
	 */
	public boolean verifyEnvelopedSignature(Element signedDocument, List<Element> shallBeSigned, 
			IdAttribute idAttribute, PublicKey validatingKey) throws DSigException
	{
		try
		{
			return verifyEnvelopedSignatureInternal(signedDocument, signedDocument, 
					shallBeSigned, idAttribute, validatingKey);
		} catch (Exception e)
		{
			throw new DSigException("Verification of enveloped signature failed", e);
		}
	}	
	
	/**
	 * @param signedDocument document which contains signed data (not necessary the whole document 
	 * need to be signed). 
	 * @param shallBeSigned list of elements in the document which should be signed.
	 * @param idAttribute what attribute holds information about element's identifier, which 
	 * @param validatingKey key which shall be used for signature verification
	 * @return true only if signature is valid
	 */
	public boolean verifyEnvelopedSignature(Document signedDocument, List<Element> shallBeSigned, 
			IdAttribute idAttribute, PublicKey validatingKey) throws DSigException
	{
		try
		{
			return verifyEnvelopedSignatureInternal(signedDocument, signedDocument.getDocumentElement(), 
					shallBeSigned, idAttribute, validatingKey);
		} catch (Exception e)
		{
			throw new DSigException("Verification of enveloped signature failed", e);
		}
	}
	
	private boolean verifyEnvelopedSignatureInternal(Node signedDocument, 
			Element signedElement, 
			List<Element> shallBeSigned, 
			IdAttribute idAttribute, 
			PublicKey validatingKey) 
			throws MarshalException, XMLSignatureException
	{
		NodeList nl = signedElement.getElementsByTagNameNS(
				XMLSignature.XMLNS, "Signature");
		if (nl.getLength() == 0)
			throw new XMLSignatureException("Document not signed");

		return verifySignatureInternal(signedDocument, signedElement, shallBeSigned, 
				idAttribute, validatingKey, nl.item(0));
	}

	private boolean verifySignatureInternal(Node signedDocument, Element signedElement, List<Element> shallBeSigned, 
			IdAttribute idAttribute, PublicKey validatingKey, Node signatureNode) 
			throws MarshalException, XMLSignatureException
	{
		if (log.isTraceEnabled())
			log.trace("Will verify signature of document:\n" + 
					DOMUtilities.dumpNodeToString(signedDocument));

		DOMValidateContext valContext = new DOMValidateContext(validatingKey,
				signatureNode);
		setResolverAttributes(valContext, signedElement, idAttribute);

		XMLSignature signature = fac.unmarshalXMLSignature(valContext);
		boolean coreValidity = signature.validate(valContext);

		if (coreValidity == false) 
			log.debug("Signature failed core validation");
		if (coreValidity == false && log.isDebugEnabled()) 
		{		
			boolean sv = signature.getSignatureValue().validate(valContext);
			log.debug("signature validation status: " + sv);
			Iterator<?> i = signature.getSignedInfo().getReferences().iterator();
			for (int j=0; i.hasNext(); j++) 
			{
				Reference ref = (Reference) i.next(); 
				boolean refValid = ref.validate(valContext);

				log.debug("ref["+j+"] validity status: " + refValid);
				String s = new String(Base64.getEncoder().encode(ref.getDigestValue()), StandardCharsets.US_ASCII);
				log.debug("ref["+j+"] digest: " + s);
				s = new String(Base64.getEncoder().encode(ref.getCalculatedDigestValue()), StandardCharsets.US_ASCII);
				log.debug("ref["+j+"] calculated digest: " + s);
			}
		} 
		if (!coreValidity)
			return false;
		
		boolean everythingSigned = checkCompletness(signature.getSignedInfo().getReferences(), 
				shallBeSigned, idAttribute);
		if (!everythingSigned) 
		{
			log.debug("Signature is correct but some of the required elements are not signed");
			return false;
		}
		
		return true;
	}

	
	/**
	 * Recursively searches in the element and its children. 
	 */
	private void setResolverAttributes(DOMCryptoContext cryptoContext, Element element, 
			IdAttribute idAttribute) throws XMLSignatureException
	{
		checkElementForIdAttribute(cryptoContext, element, idAttribute);
		NodeList nodes = element.getChildNodes();
		for (int i=0; i<nodes.getLength(); i++)
		{
			Node n = nodes.item(i);
			if (!(n instanceof Element))
				continue;
			Element e = (Element) n;
			setResolverAttributes(cryptoContext, e, idAttribute);
		}
	}
	
	private void checkElementForIdAttribute(DOMCryptoContext cryptoContext, Element element, 
			IdAttribute idAttribute) throws XMLSignatureException
	{
		if (element.hasAttributeNS(idAttribute.getNamespace(), idAttribute.getLocalName()))
		{
			String value = element.getAttributeNS(idAttribute.getNamespace(), idAttribute.getLocalName());
			if (cryptoContext.getElementById(value) != null)
			{
				log.warn("The XML document contains more then one element with the same " +
						"identifier " + value + ": " + element.getNodeName() + " and " + 
						cryptoContext.getElementById(value).getNodeName() + 
						". In case of signing this is a bug, in case of verification can mean that there is an XSW attack.");
				throw new XMLSignatureException("The XML document contains more then one element with the same " +
						"identifier " + value + ": " + element.getNodeName() + " and " + 
						cryptoContext.getElementById(value).getNodeName() + 
						". In case of signing this is a bug, in case of verification can mean that there is an XSW attack.");
			}
			cryptoContext.setIdAttributeNS(element, idAttribute.getNamespace(), idAttribute.getLocalName());
		}
	}

	
	private boolean checkCompletness(List<Reference> signedReferences, List<Element> shallBeSigned, 
			IdAttribute idAttribute)
	{
		Set<String> signedIds = new HashSet<>();
		for (Reference ref: signedReferences)
			signedIds.add(ref.getURI());

		for (Element part: shallBeSigned)
		{
			log.trace("Required part: {}", part.getTagName());
			if (!checkIfNodeSigned(signedIds, part, idAttribute))
				return false;
		}
		return true;
	}
	
	private boolean checkIfNodeSigned(Set<String> signedIds, Element el, IdAttribute idAttribute)
	{
		if (!el.hasAttributeNS(idAttribute.getNamespace(), idAttribute.getLocalName()))
		{
			log.debug("Assuming that element {" + el.getNamespaceURI() + 
					"}" + el.getLocalName() +
					" is not signed as it doesn't have id attribute");
			return false;
		}
		String idVal = el.getAttributeNS(idAttribute.getNamespace(), idAttribute.getLocalName());
		String id = "#" + idVal;
		if (signedIds.contains(id))
				return true;
		log.warn("Didn't find among signed references a required element: {"
				+ el.getNamespaceURI() + "}" + el.getLocalName() + 
				" with id " + id);
		return false;
	}
}
