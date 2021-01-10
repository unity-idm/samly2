package eu.unicore.samly2;

import static org.junit.Assert.*;

import java.io.File;
import java.security.cert.X509Certificate;

import org.apache.xmlbeans.XmlObject;
import org.junit.Test;

import xmlbeans.org.oasis.saml2.protocol.RequestAbstractType;
import xmlbeans.org.oasis.saml2.protocol.ResponseDocument;
import xmlbeans.org.oasis.saml2.protocol.StatusResponseType;
import eu.unicore.samly2.assertion.Assertion;
import eu.unicore.samly2.elements.NameID;
import eu.unicore.samly2.elements.NameIDPolicy;
import eu.unicore.samly2.elements.SAMLAttribute;
import eu.unicore.samly2.elements.Subject;
import eu.unicore.samly2.exceptions.SAMLValidationException;
import eu.unicore.samly2.proto.AssertionResponse;
import eu.unicore.samly2.proto.AttributeQuery;
import eu.unicore.samly2.proto.AuthnRequest;
import eu.unicore.samly2.proto.NameIDMappingRequest;
import eu.unicore.samly2.proto.NameIDMappingResponse;
import eu.unicore.samly2.trust.StrictSamlTrustChecker;
import eu.unicore.samly2.validators.ReplayAttackChecker;
import eu.unicore.samly2.validators.SSOAuthnResponseValidator;
import eu.unicore.security.dsig.DSigException;
import eu.unicore.security.dsig.TestBase;
import eu.unicore.security.dsig.Utils;

/**
 * Tests utility classes which are creating SAML protocol messages.
 * @author K. Benedyczak
 */
public class ProtoTest extends TestBase {

	private void sigCheck(XmlObject doc, RequestAbstractType req)
	{
		StrictSamlTrustChecker checker = new StrictSamlTrustChecker();
		checker.addTrustedIssuer(issuerDN1, SAMLConstants.NFORMAT_DN, issuerCert1[0].getPublicKey());
		try
		{
			checker.checkTrust(doc, req);
		} catch (SAMLValidationException e)
		{
			e.printStackTrace();
			fail("Signature verification failed " + e);
		}
	}

	private void sigCheck(XmlObject doc, StatusResponseType req)
	{
		StrictSamlTrustChecker checker = new StrictSamlTrustChecker();
		checker.addTrustedIssuer(issuerDN1, SAMLConstants.NFORMAT_DN, issuerCert1[0].getPublicKey());
		try
		{
			checker.checkTrust(doc, req);
		} catch (SAMLValidationException e)
		{
			e.printStackTrace();
			fail("Signature verification failed " + e);
		}
	}
	
	@Test
	public void testAttrQuery() {
		String subject = "C=PL,ST=Kujawsko-Pomorskie,L=Torun,O=UW,OU=ICM,CN=Krzysztof Benedyczak,1.2.840.113549.1.9.1=#1610676f6c6269406d61742e756d6b2e706c";

		NameID issuer = new NameID(issuerDN1, SAMLConstants.NFORMAT_DN);
		Subject sub = new Subject(subject, SAMLConstants.NFORMAT_DN);

		AttributeQuery query = new AttributeQuery(issuer.getXBean(), sub.getXBean());

		SAMLAttribute at = new SAMLAttribute("at1", SAMLConstants.AFORMAT_URI);
		query.setAttributes(new SAMLAttribute[]{at});
		try {
			query.sign(privKey1, issuerCert1);
		} catch (DSigException e) {
			e.printStackTrace();
			fail("Cannot sign AttributeQuery");
		}

		sigCheck(query.getXMLBeanDoc(), query.getXMLBean());
		assertNotNull(query.getXMLBean());
		assertNotNull(query.getXMLBeanDoc());
		assertTrue(issuer.getXBean().getFormat().equals(
				query.getXMLBean().getIssuer().getFormat()));
		assertTrue(issuer.getXBean().getStringValue().equals(
				query.getXMLBean().getIssuer().getStringValue()));
		assertTrue(sub.getXBean().getNameID().getStringValue().equals(
				query.getXMLBean().getSubject().getNameID().getStringValue()));
		assertEquals(1, query.getXMLBean().sizeOfAttributeArray());
	}

	@Test
	public void testAuthnRequest() {

		NameID name = new NameID(issuerDN1, SAMLConstants.NFORMAT_DN);

		AuthnRequest req = new AuthnRequest(name.getXBean());
		assertNotNull(req.getXMLBean());
		assertNotNull(req.getXMLBeanDoc());
		req.setFormat("format");

		assertEquals("format", req.getXMLBean().getNameIDPolicy().getFormat());

		try {
			req.sign(privKey1, issuerCert1);
		} catch (DSigException e) {
			e.printStackTrace();
			fail("Cannot sign AuthnRequest");
		}

		sigCheck(req.getXMLBeanDoc(), req.getXMLBean());
	}

	@Test
	public void testNameIdMapReq() {
		NameID name = new NameID(issuerDN1, SAMLConstants.NFORMAT_DN);
		NameID mapname = new NameID("test@test.com",
				SAMLConstants.NFORMAT_EMAIL);
		NameIDPolicy policy = new NameIDPolicy(SAMLConstants.NFORMAT_UNSPEC);

		NameIDMappingRequest req = new NameIDMappingRequest(name.getXBean(), mapname.getXBean(),
				policy.getXBean());

		try {
			req.sign(privKey1, issuerCert1);
		} catch (DSigException e) {
			e.printStackTrace();
			fail("Cannot sign NameIDMappingRequest");
		}
		sigCheck(req.getXMLBeanDoc(), req.getXMLBean());
	}

	@Test
	public void testNameIdMapResp() {
		NameID name = new NameID(issuerDN1, SAMLConstants.NFORMAT_DN);
		NameID mapname = new NameID("test@test.com",
				SAMLConstants.NFORMAT_EMAIL);
		NameIDMappingResponse resp = new NameIDMappingResponse(name.getXBean(),
				"example.com", mapname.getXBean());
		
		try {

			resp.sign(privKey1, issuerCert1);
		} catch (Exception e) {
			e.printStackTrace();
			fail("Cannot sign NameIDMappingResponse");
		}

		sigCheck(resp.getXMLBeanDoc(), resp.getXMLBean());
	}

	@Test
	public void testAssertionResp() {
		NameID issuer = new NameID(issuerDN1, SAMLConstants.NFORMAT_DN);

		AssertionResponse resp = new AssertionResponse(issuer.getXBean(), "1234");
		Assertion as = new Assertion();
		as.addAttribute(new SAMLAttribute("a", "b"));
		resp.addAssertion(as);

		try {

			resp.sign(privKey1, issuerCert1);
		} catch (Exception e) {
			e.printStackTrace();
			fail("Cannot sign NameIDMappingResponse");
		}

		sigCheck(resp.getXMLBeanDoc(), resp.getXMLBean());
		assertEquals(issuerDN1, resp.getXMLBean().getIssuer().getStringValue());
		assertEquals(1, resp.getXMLBean().sizeOfAssertionArray());
		assertEquals(1, resp.getXMLBean().getAssertionArray(0).sizeOfAttributeStatementArray());
		assertEquals(1, resp.getXMLBean().getAssertionArray(0).getAttributeStatementArray(0).sizeOfAttributeArray());
		assertEquals("a", resp.getXMLBean().getAssertionArray(0).getAttributeStatementArray(0).getAttributeArray(0).getName());
	}

	@Test
	public void testAuthnResp() throws Exception {
		
		ResponseDocument authenticationResponseDoc = ResponseDocument.Factory.parse(
				new File("src/test/resources/responseDocSigned.xml"));
		byte[][] certs = authenticationResponseDoc.getResponse().getSignature().getKeyInfo().getX509DataArray(0).getX509CertificateArray();
		X509Certificate[] c = Utils.deserializeCertificateChain(certs);
		StrictSamlTrustChecker trustChecker = new StrictSamlTrustChecker();
		trustChecker.addTrustedIssuer("http://centos6-unity1:8080/simplesaml/saml2/idp/metadata.php", null, 
				c[0].getPublicKey());
		SSOAuthnResponseValidator validator = new SSOAuthnResponseValidator(null, null, 
				"SAMLY2lib_msg_19155ef4173009c5b5d93ec3c07edcdc39d281b15cef0e28", 
				360000000000L, trustChecker, new ReplayAttackChecker(), SAMLBindings.HTTP_POST);
		
		validator.validate(authenticationResponseDoc);
		
	}

}
