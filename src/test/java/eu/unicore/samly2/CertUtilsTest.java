package eu.unicore.samly2;

import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;

import eu.unicore.security.CertificateUtils;
import eu.unicore.security.dsig.TestBase;

public class CertUtilsTest extends TestBase{

	public void test1(){
		String subject=null;
		
		
		subject=CertificateUtils.safePrintSubject(issuerCert1);
		assertEquals(issuerDN1,subject);
		
		subject=CertificateUtils.safePrintSubject(issuerCert1[0]);
		assertEquals(issuerDN1,subject);
		
		try {
			CertificateUtils.verifyCertificate(issuerCert1, true, true);
		} catch (CertificateExpiredException e) {
			e.printStackTrace();
			fail("Certificate is not expired,bad utils verification");
		} catch (CertificateNotYetValidException e) {
			e.printStackTrace();
			fail("Certificate is valid,bad utils verification");
		}
		assertTrue(true);
		
		
		
		
	}
	
}
