/*
 * Copyright (c) 2007, 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on Apr 24, 2007
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.security.dsig;

import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.Vector;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dom.DOMCryptoContext;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI;
import org.apache.log4j.Logger;
import org.apache.xmlbeans.XmlBase64Binary;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import xmlbeans.org.w3.x2000.x09.xmldsig.KeyInfoType;
import xmlbeans.org.w3.x2000.x09.xmldsig.X509DataType;


/**
 * Provides high-level API for signing and verifying XML signatures.
 * Only implements those kind of signatures that are relevant for
 * UNICORE security infrastructure.
 * @author K. Benedyczak
 */
public class DigSignatureUtil
{
	private static final Logger log = Logger.getLogger("unicore.security.dsig." + 
		DigSignatureUtil.class.getSimpleName());
	private XMLSignatureFactory fac = null;
	
	public DigSignatureUtil() throws DSigException
	{
		try
		{
			Security.addProvider(new XMLDSigRI());
			fac = XMLSignatureFactory.getInstance("DOM", "ApacheXMLDSig");
			double ver = fac.getProvider().getVersion();
			if (ver < 1.50)
				log.error("xmlsec library is not properly configured, XML dsig will sometimes fail! " +
					"Currently version " + ver + " is used, while at least version 1.44 should be used." +
					" Most often this means that xmlsec-x.xx.jar is not in Java endorsed directory.");
		} catch (Exception e)
		{
			throw new DSigException("Initialization of digital signature " +
					"engine failed", e);
		}
	}
	
	/**
	 * Generates an enveloped signature.
	 * @param privKey private key used for signing
	 * @param pubKey optional public key which is added to KeyInfo 
	 * @param cert optional certificate which is added to KeyInfo, typically use it, not the pub key.
	 * @param docToSign document which will will be signed (whole).
	 * @param insertBefore where to insert the dsig:Signature element
	 * @param idAttribute what is the id attribute, which should be used as a reference. The root element
	 * of the docToSign must possess this attribute.
	 */
	public void genEnvelopedSignature(PrivateKey privKey, PublicKey pubKey, 
			X509Certificate []cert, Document docToSign, Node insertBefore, IdAttribute idAttribute) 
		throws DSigException
	{
		try
		{
			genEnvelopedSignatureInternal(privKey, pubKey, cert, docToSign, insertBefore, idAttribute);
		} catch (Exception e)
		{
			throw new DSigException("Creation of enveloped signature " +
					"failed", e);
		}
	}
	
	private void genEnvelopedSignatureInternal(PrivateKey privKey, PublicKey pubKey,  
			X509Certificate []cert, Document docToSign, Node insertBefore, IdAttribute idAttribute) 
		throws MarshalException, XMLSignatureException,	NoSuchAlgorithmException, 
		InvalidAlgorithmParameterException, KeyException, CertificateExpiredException, CertificateNotYetValidException
	{
		
		DigestMethod digistMethod = fac.newDigestMethod(DigestMethod.SHA1, null);
		Vector<Transform> transforms = new Vector<Transform>(); 

		transforms.add(fac.newTransform(Transform.ENVELOPED, 
				(TransformParameterSpec) null));
		transforms.add(fac.newTransform(CanonicalizationMethod.EXCLUSIVE, 
			(TransformParameterSpec) null));
		CanonicalizationMethod canMethod = fac.newCanonicalizationMethod(
				CanonicalizationMethod.EXCLUSIVE,
				(C14NMethodParameterSpec) null);
		
		SignatureMethod sigMethod;
		if (privKey instanceof RSAPrivateKey)
			sigMethod = fac.newSignatureMethod(
				SignatureMethod.RSA_SHA1, null);
		else if (privKey instanceof DSAPrivateKey)
			sigMethod = fac.newSignatureMethod(
				SignatureMethod.DSA_SHA1, null);
		else
			throw new KeyException("Unsupported private key algorithm " +
				"(must be DSA or RSA) :" + privKey.getAlgorithm());

		Element elToSign = docToSign.getDocumentElement();
		
		if (!elToSign.hasAttributeNS(idAttribute.getNamespace(), idAttribute.getLocalName()))
			throw new IllegalArgumentException("The document to be signed doesn't contain the requested ID attribtue " + idAttribute);
		String id = elToSign.getAttributeNS(idAttribute.getNamespace(), idAttribute.getLocalName());
		if (id != null)
			id = "#" + id;
		
		Reference ref = fac.newReference(id, 
					digistMethod,
					transforms,
					null, null);
		SignedInfo si = fac.newSignedInfo(canMethod, sigMethod,
					Collections.singletonList(ref));

		if (log.isTraceEnabled())
			log.trace("Will generate signature of a document:\n" + 
					dumpDOMToString(docToSign));

		DOMSignContext dsc = null;
		if (insertBefore == null)
			dsc = new DOMSignContext(privKey, elToSign);
		else
			dsc = new DOMSignContext(privKey, elToSign, insertBefore);
		
		dsc.setIdAttributeNS(elToSign, idAttribute.getNamespace(), idAttribute.getLocalName());
		
		
		//hack to overcome gateway/ActiveSOAP bugs with default prefixes...
		// -> only relevant for gateway version < 6.3.0  
		dsc.putNamespacePrefix(
			"http://www.w3.org/2000/09/xmldsig#", 
			"dsig");
		KeyInfo ki = null;
		KeyInfoFactory kif = fac.getKeyInfoFactory();
		List<XMLStructure> kiVals = new ArrayList<>();
		if (pubKey != null)
		{
			KeyValue kv = kif.newKeyValue(pubKey);
			kiVals.add(kv);
		}
		if (cert != null)
		{
			ArrayList<X509Certificate> certList = 
				new ArrayList<X509Certificate>();
			for (X509Certificate c: cert)
				certList.add(c);
			X509Data x509Data = kif.newX509Data(certList);
			kiVals.add(x509Data);
		}
		if (kiVals.size() > 0)
			ki = kif.newKeyInfo(kiVals);
		
		XMLSignature signature = fac.newXMLSignature(si, ki);

		signature.sign(dsc);

		if (log.isTraceEnabled())
			log.trace("Signed document:\n" + 
					dumpDOMToString(docToSign));

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
			return verifyEnvelopedSignatureInternal(signedDocument, shallBeSigned, idAttribute, validatingKey);
		} catch (Exception e)
		{
			throw new DSigException("Verification of enveloped signature " +
					"failed", e);
		}
	}	
	
	private boolean verifyEnvelopedSignatureInternal(Document signedDocument, List<Element> shallBeSigned, 
			IdAttribute idAttribute, PublicKey validatingKey) 
			throws MarshalException, XMLSignatureException
	{
		NodeList nl = signedDocument.getElementsByTagNameNS(
				XMLSignature.XMLNS, "Signature");
		if (nl.getLength() == 0)
			throw new XMLSignatureException("Document not signed");

		return verifySignatureInternal(signedDocument, shallBeSigned, idAttribute, validatingKey, nl.item(0));
	}

	/**
	 * 
	 * @param signedDocument document which contains signed data (not necessary the whole document 
	 * need to be signed). 
	 * @param shallBeSigned list of elements in the document which should be signed.
	 * @param idAttribute what attribute holds information about element's identifier, which 
	 * @param validatingKey key which shall be used for signature verification
	 * @param signatureNode a node (which need not to be in the document) with signature.
	 * @return true only if signature is valid
	 */
	public boolean verifyDetachedSignature(Document signedDocument, List<Element> shallBeSigned, 
			IdAttribute idAttribute, PublicKey validatingKey, Node signatureNode) throws DSigException
	{
		try
		{
			return verifySignatureInternal(signedDocument, shallBeSigned, idAttribute, validatingKey, 
					signatureNode);
		} catch (Exception e)
		{
			throw new DSigException("Verification of detached signature " +
					"failed", e);
		}
	}	


	private boolean verifySignatureInternal(Document signedDocument, List<Element> shallBeSigned, 
			IdAttribute idAttribute, PublicKey validatingKey, Node signatureNode) 
			throws MarshalException, XMLSignatureException
	{
		if (log.isTraceEnabled())
			log.trace("Will verify signature of document:\n" + 
					dumpDOMToString(signedDocument));

		DOMValidateContext valContext = new DOMValidateContext(validatingKey,
				signatureNode);
		setResolverAttributes(valContext, signedDocument.getDocumentElement(), idAttribute);

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
		
		@SuppressWarnings("unchecked")
		boolean everythingSigned = checkCompletness(signature.getSignedInfo().getReferences(), 
				shallBeSigned, signedDocument, idAttribute);
		if (!everythingSigned) 
		{
			log.debug("Signature is correct but some of the required elements are not signed");
			return false;
		}
		
		return true;
	}

	
	public static KeyInfoType generateX509KeyInfo(X509Certificate[] certs) 
		throws CertificateEncodingException
	{
		KeyInfoType ret = KeyInfoType.Factory.newInstance();
		X509DataType x509Data = ret.addNewX509Data();
		for (X509Certificate cert: certs)
		{
			XmlBase64Binary binCert = x509Data.addNewX509Certificate();
			byte []certRaw = cert.getEncoded();
			binCert.setByteArrayValue(certRaw);
		}
		return ret;
	}
	
	public List<?> getReferencesFromSignature(Node signatureNode) 
		throws DSigException
	{
		DOMStructure xml = new DOMStructure(signatureNode);
		XMLSignature signature;
		try
		{
			signature = fac.unmarshalXMLSignature(xml);
		} catch (MarshalException e)
		{
			throw new DSigException("Can't unmarshal signature", e);
		}
		return signature.getSignedInfo().getReferences();
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

	
	public boolean checkCompletness(List<Reference> signedReferences, List<Element> shallBeSigned, 
			Document signedDocument, IdAttribute idAttribute)
	{
		Set<String> signedIds = new HashSet<String>();
		for (Reference ref: signedReferences)
			signedIds.add(ref.getURI());

		for (Element part: shallBeSigned)
		{
			log.trace("Required part: " + part.getTagName());
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

	
	public static String dumpDOMToString(Element node)
	{
		return dumpNodeToString(node);
	}
	
	public static String dumpDOMToString(Document node)
	{
		return dumpNodeToString(node);
	}

	private static String dumpNodeToString(Node document)
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
