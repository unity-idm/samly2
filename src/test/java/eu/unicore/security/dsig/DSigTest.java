package eu.unicore.security.dsig;


import java.io.InputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Node;


/**
 * Tests generation and verification of enveloped signature.
 * @author K. Benedyczak
 */
public class DSigTest extends TestBase
{
	public void testSignVerify()
	{
		try
		{
			DigSignatureUtil dsigEngine = new DigSignatureUtil();
			Document doc = readDoc("/doc.xml");
			
			Node n = doc.getDocumentElement().getChildNodes().item(1);
			PublicKey pubKey = issuerCert1[0].getPublicKey();
			dsigEngine.genEnvelopedSignature(privKey1, pubKey, issuerCert1, 
				doc, n);

			assertTrue(dsigEngine.verifyEnvelopedSignature(doc, pubKey));
			
		} catch (Exception e)
		{
			e.printStackTrace();
			fail(e.getMessage());
		}
		assertTrue(true);
	}
	
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

			boolean result = dsigEngine.verifyEnvelopedSignature(doc, pubKey);
			assertTrue(result);
		} catch (Exception e)
		{
			e.printStackTrace();
			fail(e.getMessage());
		}
		assertTrue(true);
	}
	
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
