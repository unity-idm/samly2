/*
 * Copyright (c) 2007, 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on Apr 24, 2007
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.security.dsig;

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
import java.util.Collections;
import java.util.List;
import java.util.Vector;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.XMLStructure;
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
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;

import org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.xmlbeans.XmlBase64Binary;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

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
	private static final Logger log = LogManager.getLogger(LoggerPfx.DSIG_PFX + 
		DigSignatureUtil.class.getSimpleName());
	private XMLSignatureFactory fac = null;
	
	public DigSignatureUtil() throws DSigException
	{
		try
		{
			Security.addProvider(new XMLDSigRI());
			fac = XMLSignatureFactory.getInstance("DOM", "ApacheXMLDSig");
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
		
		SignatureMethod sigMethod = fac.newSignatureMethod(getSAMLSignatureAlgorithmForPrivateKey(privKey), null);

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
	
	public static String getSAMLSignatureAlgorithmForPrivateKey(PrivateKey privKey) throws KeyException
	{
		if (privKey instanceof RSAPrivateKey)
			return SignatureMethod.RSA_SHA1;
		else if (privKey instanceof DSAPrivateKey)
			return SignatureMethod.DSA_SHA1;
		else
			throw new KeyException("Unsupported private key algorithm " +
				"(must be DSA or RSA) :" + privKey.getAlgorithm());
	}
	
	public static String getJCASignatureAlgorithmForPrivateKey(PrivateKey privKey) throws KeyException
	{
		if (privKey instanceof RSAPrivateKey)
			return "SHA1withRSA";
		else if (privKey instanceof DSAPrivateKey)
			return "SHA1withDSA";
		else
			throw new KeyException("Unsupported private key algorithm " +
				"(must be DSA or RSA) :" + privKey.getAlgorithm());
	}

	public static String getJCASignatureAlgorithmForSAMLSignatureAlgorithm(String samlSignatureAlgorithm) throws KeyException
	{
		if (SignatureMethod.RSA_SHA1.equals(samlSignatureAlgorithm))
			return "SHA1withRSA";
		else if (SignatureMethod.DSA_SHA1.equals(samlSignatureAlgorithm))
			return "SHA1withDSA";
		else
			throw new KeyException("Unsupported signature algorithm " 
					+ "(must be http://www.w3.org/2000/09/xmldsig#rsa-sha1 or "
					+ "http://www.w3.org/2000/09/xmldsig#dsa-sha1) :" 
					+ samlSignatureAlgorithm);
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
	 * @deprecated use {@link DOMUtilities} methods instead
	 */
	@Deprecated
	public static String dumpDOMToString(Element node)
	{
		return DOMUtilities.dumpNodeToString(node);
	}
	
	/**
	 * @deprecated use {@link DOMUtilities} methods instead
	 */
	public static String dumpDOMToString(Document node)
	{
		return DOMUtilities.dumpNodeToString(node);
	}
}
