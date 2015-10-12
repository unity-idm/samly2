package eu.unicore.security.dsig;


import static org.junit.Assert.*;

import java.io.InputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Collections;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import eu.unicore.samly2.trust.SamlTrustChecker;


/**
 * Tests generation and verification of enveloped signature.
 * @author K. Benedyczak
 */
public class DSigTest extends TestBase
{
	@Test
	public void testSignVerify()
	{
		try
		{
			DigSignatureUtil dsigEngine = new DigSignatureUtil();
			Document doc = readDoc("/doc.xml");
			
			Node n = doc.getDocumentElement().getChildNodes().item(1);
			PublicKey pubKey = issuerCert1[0].getPublicKey();
			dsigEngine.genEnvelopedSignature(privKey1, pubKey, issuerCert1, 
				doc, n, SamlTrustChecker.ASSERTION_ID_QNAME);

			assertTrue(dsigEngine.verifyEnvelopedSignature(doc, Collections.singletonList(doc.getDocumentElement()), 
					SamlTrustChecker.ASSERTION_ID_QNAME, pubKey));
			
		} catch (Exception e)
		{
			e.printStackTrace();
			fail(e.getMessage());
		}
		assertTrue(true);
	}
	
	@Test
	public void testVerify()
	{
		try
		{
			DigSignatureUtil dsigEngine = new DigSignatureUtil();
			Document doc = readDoc("/docSigned.xml");
			
			BigInteger modulus = new BigInteger("163777238822666015285329706279830595411974064586059702871587099431512157455719495774518770867278091194963281647181853106959836263061780091305987288645684760669758102471364248456086999347113921145640831970575719191169166816785623263506972893282383928337258596366986798122055894688767641149446988631156789299337");
			BigInteger exponent = new BigInteger("65537");
			RSAPublicKeySpec keySpec = new RSAPublicKeySpec(modulus, exponent);
			KeyFactory kf = KeyFactory.getInstance("RSA");
			PublicKey pubKey = kf.generatePublic(keySpec);

			IdAttribute WSS_ID = new IdAttribute("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd", "Id");
			boolean result = dsigEngine.verifyEnvelopedSignature(doc, 
					Collections.singletonList((Element)doc.getDocumentElement().getLastChild()), 
					WSS_ID, pubKey);
			assertTrue(result);
		} catch (Exception e)
		{
			e.printStackTrace();
			fail(e.getMessage());
		}
		assertTrue(true);
	}
	
	@Test
	public void testStandaloneCanonizer()
	{
		StandaloneCanonizer instance;
		try
		{
			instance = new StandaloneCanonizer();
			Document doc =	readDoc("/docSigned.xml");
			String res = instance.fireCanon(doc, false);
			
			
			System.out.println("\n\nCanonized document:\n" + res);
			
			assertFalse(res.contains("<!--COMMENT-TO-REMOVE-->"));
		} catch (Exception e)
		{
			e.printStackTrace();
			fail(e.getMessage());
		}
	}
	
	private Document readDoc(String file) throws Exception
	{
		DocumentBuilderFactory builderFactory = 
			DocumentBuilderFactory.newInstance();
		builderFactory.setNamespaceAware(true);
		DocumentBuilder docBuilder = builderFactory.newDocumentBuilder();
		InputStream is = getClass().getResourceAsStream(file);
		return docBuilder.parse(is);
	}
}
