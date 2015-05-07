/*
 * Copyright (c) 2014 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.security.enc;

import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

import javax.crypto.KeyGenerator;

import org.apache.log4j.Logger;
import org.apache.xml.security.encryption.EncryptedData;
import org.apache.xml.security.encryption.EncryptedKey;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.keys.content.X509Data;
import org.apache.xml.security.utils.EncryptionConstants;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import eu.unicore.security.dsig.DigSignatureUtil;

/**
 * Support code for encrypting XML
 * @author K. Benedyczak
 */
public class EncryptionUtil
{
	private static final Logger log = Logger.getLogger("unicore.security.enc." + 
			EncryptionUtil.class.getSimpleName());

	static
	{
		org.apache.xml.security.Init.init();	
	}
	
	public Document decrypt(Document xml, PrivateKey key) throws Exception
	{
		String namespaceURI = EncryptionConstants.EncryptionSpecNS;
		String localName = EncryptionConstants._TAG_ENCRYPTEDDATA;
		Element encryptedDataElement = (Element)xml.getElementsByTagNameNS(namespaceURI,
						localName).item(0);

		XMLCipher xmlCipher = XMLCipher.getInstance();
		xmlCipher.init(XMLCipher.DECRYPT_MODE, null);
		xmlCipher.setKEK(key);
		
		Document ret = xmlCipher.doFinal(xml, encryptedDataElement);
		
		if (log.isTraceEnabled())
			log.trace("Decrypted document:\n" + DigSignatureUtil.dumpDOMToString(ret));
		
		return ret;
	}

	public Document encrypt(Document xml, X509Certificate encCertificate, int keySize) throws Exception
	{
		return encrypt(xml, encCertificate.getPublicKey(), encCertificate, keySize);
	}
	
	public Document encrypt(Document xml, PublicKey pubKey, int keySize) throws Exception
	{
		return encrypt(xml, pubKey, null, keySize);
	}
	
	private Document encrypt(Document xml, PublicKey pubKey, X509Certificate encCertificate, int keySize) throws Exception
	{
		String fullAlgoName = getFullAlgoName(keySize, false);
		Key symmetricKey = generateSymmetricKey("AES", keySize);

		XMLCipher keyCipher = XMLCipher.getInstance(XMLCipher.RSA_OAEP);
		keyCipher.init(XMLCipher.WRAP_MODE, pubKey);
		EncryptedKey encryptedKey = keyCipher.encryptKey(xml, symmetricKey);
		
		XMLCipher xmlCipher = XMLCipher.getInstance(fullAlgoName);
		xmlCipher.init(XMLCipher.ENCRYPT_MODE, symmetricKey);

		EncryptedData encryptedDataElement = xmlCipher.getEncryptedData();
		KeyInfo keyInfo = new KeyInfo(xml);
		keyInfo.add(encryptedKey);
		if (encCertificate != null)
		{
			X509Data x509Data = new X509Data(xml);
			x509Data.addCertificate(encCertificate);
			keyInfo.add(x509Data);
		}
		encryptedDataElement.setKeyInfo(keyInfo);
		
		Element elementToEncrypt = xml.getDocumentElement();
		
		return xmlCipher.doFinal(xml, elementToEncrypt, false);
	}
	
	private Key generateSymmetricKey(String algo, int keySize) throws NoSuchAlgorithmException
	{
		KeyGenerator keyGenerator = KeyGenerator.getInstance(algo);
		keyGenerator.init(keySize);
		return keyGenerator.generateKey();
	}
	
	private String getFullAlgoName(int keySize, boolean keyWrap)
	{
		switch (keySize)
		{
		case 128: 
			return keyWrap ? XMLCipher.AES_128_KeyWrap : XMLCipher.AES_128;
		case 192: 
			return keyWrap ? XMLCipher.AES_192_KeyWrap : XMLCipher.AES_192;
		case 256: 
			return keyWrap ? XMLCipher.AES_256_KeyWrap : XMLCipher.AES_256;
		default:
			throw new IllegalArgumentException("Only 128, 192 and 256 are valid encryption key sizes");
		}
	}
}
