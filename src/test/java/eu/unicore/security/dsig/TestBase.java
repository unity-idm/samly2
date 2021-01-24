package eu.unicore.security.dsig;


import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import org.apache.xmlbeans.XmlOptions;
import org.junit.Before;

public abstract class TestBase
{
	public static final String PASSWORD = "dummypassword";
	public static final String ALIAS = "a1";
	
	public static final String KEYSTORE1 = "keystoreRSA1.jks";
	public static final String KEYSTORE2 = "keystoreRSA2.jks";
	public static final String KEYSTORE3 = "keystoreDSA1.jks";
	public static final String KEYSTORE4 = "keystoreDSA2.jks";
	public static final String KEYSTORE_EXP = "keystoreExpired.jks";
	
	
	private KeyStore ks1, ks2, ks3, ks4, ksExp;
	protected X509Certificate[] issuerCert1, receiverCert1;
	protected X509Certificate[] issuerCert2, receiverCert2;
	protected X509Certificate[] expiredCert;
	protected String issuerDN1, issuerDN2;
	protected String receiverDN1, receiverDN2, expiredDN;
	protected PrivateKey privKey1, privKey2, privKey3, privKeyExpired;
	protected XmlOptions xmlOpts;
	
	
	
	@Before
	public void setUp()
	{
		try
		{
			xmlOpts = new XmlOptions().setSavePrettyPrint();
			ks1 = loadKeystore(KEYSTORE1);
			ks2 = loadKeystore(KEYSTORE2);
			ks3 = loadKeystore(KEYSTORE3);
			ks4 = loadKeystore(KEYSTORE4);
			ksExp = loadKeystore(KEYSTORE_EXP);
			
			issuerCert1 = convertChain(ks1.getCertificateChain(ALIAS));
			receiverCert1 = convertChain(ks2.getCertificateChain(ALIAS));
			issuerCert2 = convertChain(ks3.getCertificateChain(ALIAS));
			receiverCert2 = convertChain(ks4.getCertificateChain(ALIAS));
			expiredCert = convertChain(ksExp.getCertificateChain(ALIAS));
			
			
			privKey1 = (PrivateKey) ks1.getKey(ALIAS, PASSWORD.toCharArray());
			privKey2 = (PrivateKey) ks3.getKey(ALIAS, PASSWORD.toCharArray());
			privKey3 = (PrivateKey) ks2.getKey(ALIAS, PASSWORD.toCharArray());
			privKeyExpired = (PrivateKey) ksExp.getKey(ALIAS, PASSWORD.toCharArray());
			
			issuerDN1 = issuerCert1[0].getSubjectX500Principal().getName();
			receiverDN1 = receiverCert1[0].getSubjectX500Principal().getName();
			issuerDN2 = issuerCert2[0].getSubjectX500Principal().getName();
			receiverDN2 = receiverCert2[0].getSubjectX500Principal().getName();
			expiredDN = expiredCert[0].getSubjectX500Principal().getName();
		} catch (Exception e)
		{
			throw new RuntimeException(e);
		}
	}
	
	public static KeyStore loadKeystore(String path) throws Exception
	{
		try
		{
			KeyStore keystore = KeyStore.getInstance("JKS");
			InputStream is = TestBase.class.getResourceAsStream("/" + path);
			keystore.load(is, PASSWORD.toCharArray());
			return keystore;
		} catch (Exception e)
		{
			throw new RuntimeException("Can't load keystore", e);
		}
	}
	
	public static X509Certificate[] convertChain(Certificate[] chain)
	{
		X509Certificate[] ret = new X509Certificate[chain.length];
		for (int i=0; i<chain.length; i++)
			ret[i] = (X509Certificate) chain[i];
		return ret;
	}
}
