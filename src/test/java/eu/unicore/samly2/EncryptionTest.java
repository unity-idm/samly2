/*
 * Copyright (c) 2014 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.samly2;

import java.io.File;
import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.List;

import org.apache.commons.io.FileUtils;
import org.apache.xmlbeans.XmlOptions;
import org.junit.Test;

import eu.emi.security.authn.x509.impl.CertificateUtils;
import eu.emi.security.authn.x509.impl.CertificateUtils.Encoding;
import eu.emi.security.authn.x509.impl.KeystoreCredential;
import eu.unicore.samly2.assertion.Assertion;
import eu.unicore.samly2.assertion.AssertionParser;
import eu.unicore.samly2.trust.StrictSamlTrustChecker;
import eu.unicore.security.dsig.TestBase;
import xmlbeans.org.oasis.saml2.assertion.AssertionDocument;
import xmlbeans.org.oasis.saml2.assertion.EncryptedAssertionDocument;
import xmlbeans.org.oasis.saml2.protocol.ResponseDocument;

public class EncryptionTest extends TestBase
{
	@Test
	public void testEncryption() throws Exception
	{
		Assertion tested = new Assertion();
		tested.setIssuer("fooo", SAMLConstants.NFORMAT_ENTITY);
		tested.sign(privKey1);
		
		AssertionDocument testedDoc = tested.getXMLBeanDoc();
		
		String asTxt = testedDoc.xmlText(new XmlOptions().setSavePrettyPrint());
		System.out.println("Source:\n" + asTxt + "\n");
		
		EncryptedAssertionDocument encrypted = tested.encrypt(issuerCert1[0], 128);
		
		System.out.println("Encrypted:\n" + encrypted.xmlText(new XmlOptions().setSavePrettyPrint()) + "\n");
		
		AssertionParser aparser = new AssertionParser(encrypted, privKey1);
		
		AssertionDocument asDoc = aparser.getXMLBeanDoc();
		String after2 = asDoc.xmlText();
		System.out.println("Decrypted, after XMLBeans:\n" + after2 + "\n");

		aparser.validateSignature(issuerCert1[0].getPublicKey());
	}
	
	@Test
	public void testOfResponse() throws Exception
	{
		String respXml = FileUtils.readFileToString(new File("src/test/resources/encryptedResp.xml"),
				StandardCharsets.UTF_8);
		ResponseDocument responseDoc = ResponseDocument.Factory.parse(respXml);
		
		KeystoreCredential ksCred = new KeystoreCredential("src/test/resources/encryptionKeystore.p12", 
				"the!uvos".toCharArray(), "the!uvos".toCharArray(), "uvos", "pkcs12");
		X509Certificate cert = CertificateUtils.loadCertificate(
				new FileInputStream("src/test/resources/encryptedAssertionSigner.pem"), 
				Encoding.PEM);
		
		List<SAMLUtils.XMLBeansWithDom<AssertionDocument>> assertions = SAMLUtils.extractAllAssertions(
				responseDoc.getResponse(), ksCred.getKey());
		AssertionDocument asDoc = assertions.get(0).xmlBean;
		System.out.println("Decrypted, after XMLBeans:\n" + asDoc.xmlText() + "\n");
		Assertion a = new Assertion(asDoc);
		a.validateSignature(cert.getPublicKey());
	}
	
	@Test
	public void testEncryptedResponseTrustValidationUsesAssertionElement() throws Exception
	{
		String respXml = FileUtils.readFileToString(new File("src/test/resources/encryptedResp.xml"),
				StandardCharsets.UTF_8);
		ResponseDocument responseDoc = ResponseDocument.Factory.parse(respXml);
		KeystoreCredential ksCred = new KeystoreCredential("src/test/resources/encryptionKeystore.p12",
				"the!uvos".toCharArray(), "the!uvos".toCharArray(), "uvos", "pkcs12");

		List<SAMLUtils.XMLBeansWithDom<AssertionDocument>> assertions = SAMLUtils.extractAllAssertions(
				responseDoc.getResponse(), ksCred.getKey());
		SAMLUtils.XMLBeansWithDom<AssertionDocument> assertion = assertions.get(0);


		PublicKey signingKey = SAMLUtils.getIssuerFromSignature(assertion.xmlBean.getAssertion().getSignature())[0]
				.getPublicKey();

		StrictSamlTrustChecker trustChecker = new StrictSamlTrustChecker();
		trustChecker.addTrustedIssuer(assertion.xmlBean.getAssertion().getIssuer().getStringValue(),
				assertion.xmlBean.getAssertion().getIssuer().getFormat(), signingKey);
		trustChecker.checkTrust(assertion);
	}
}
