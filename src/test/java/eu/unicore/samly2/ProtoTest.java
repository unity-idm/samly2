package eu.unicore.samly2;

import eu.unicore.samly2.SAMLConstants;
import eu.unicore.samly2.elements.NameID;
import eu.unicore.samly2.elements.NameIDPolicy;
import eu.unicore.samly2.elements.Subject;
import eu.unicore.samly2.exceptions.SAMLParseException;
import eu.unicore.samly2.exceptions.SAMLProtocolException;
import eu.unicore.samly2.proto.AttributeQuery;
import eu.unicore.samly2.proto.AuthnRequest;
import eu.unicore.samly2.proto.NameIDMappingRequest;
import eu.unicore.samly2.proto.NameIDMappingResponse;
import eu.unicore.security.dsig.DSigException;
import eu.unicore.security.dsig.TestBase;

public class ProtoTest extends TestBase {

	public void testAttrQuery() {
		String subject = "C=PL,ST=Kujawsko-Pomorskie,L=Torun,O=UW,OU=ICM,CN=Krzysztof Benedyczak,1.2.840.113549.1.9.1=#1610676f6c6269406d61742e756d6b2e706c";

		NameID name = new NameID(issuerDN1, SAMLConstants.NFORMAT_DN);
		Subject sub = new Subject(subject, SAMLConstants.NFORMAT_DN);

		AttributeQuery query = new AttributeQuery(name, sub);
		assertNotNull(query.getID());
		assertTrue(name.getXBean().xmlText().equals(
				query.getIssuer().getXBean().xmlText()));
		assertTrue(sub.getXBean().xmlText().equals(
				query.getSubject().getXBean().xmlText()));

		try {
			query.sign(privKey1, issuerCert1);
		} catch (DSigException e) {
			e.printStackTrace();
			fail("Cannot sign AttributeQuery");
		}
		assertTrue(query.isSigned());
		try {
			assertTrue(query.isCorrectlySigned(issuerCert1[0].getPublicKey()));
		} catch (DSigException e) {
			e.printStackTrace();
			fail("Cannot check AttributeQuery signature");
		}

	}

	public void testAuthnRequest() {

		NameID name = new NameID(issuerDN1, SAMLConstants.NFORMAT_DN);

		AuthnRequest req = new AuthnRequest(name);
		assertNotNull(req.getID());
		req.setConsumerURL("example.com");

		assertEquals("example.com", req.getDoc().getAuthnRequest()
				.getAssertionConsumerServiceURL());

		try {
			req.sign(privKey1, issuerCert1);
		} catch (DSigException e) {
			e.printStackTrace();
			fail("Cannot sign AuthnRequest");
		}
		assertTrue(req.isSigned());
		try {
			assertTrue(req.isCorrectlySigned(issuerCert1[0].getPublicKey()));
		} catch (DSigException e) {
			e.printStackTrace();
			fail("Cannot check AuthnRequest signature");
		}

	}

	public void testNameIdMapReq() {
		NameID name = new NameID(issuerDN1, SAMLConstants.NFORMAT_DN);
		NameID mapname = new NameID("test@test.com",
				SAMLConstants.NFORMAT_EMAIL);
		NameIDPolicy policy = new NameIDPolicy(SAMLConstants.NFORMAT_UNSPEC);

		NameIDMappingRequest req = new NameIDMappingRequest(name, mapname,
				policy);

		try {
			req.parse();
		} catch (SAMLProtocolException e) {
			e.printStackTrace();
			fail("Cannot parse correct NameIDMappingRequest");
		}
		assertTrue(true);

		try {
			req.sign(privKey1, issuerCert1);
		} catch (DSigException e) {
			e.printStackTrace();
			fail("Cannot sign NameIDMappingRequest");
		}
		assertTrue(req.isSigned());
		try {
			assertTrue(req.isCorrectlySigned(issuerCert1[0].getPublicKey()));
		} catch (DSigException e) {
			e.printStackTrace();
			fail("Cannot check NameIDMappingRequest signature");
		}

	}

	public void testNameIdMapResp() {
		NameID name = new NameID(issuerDN1, SAMLConstants.NFORMAT_DN);
		NameID mapname = new NameID("test@test.com",
				SAMLConstants.NFORMAT_EMAIL);
		NameIDMappingResponse resp = new NameIDMappingResponse(name,
				"example.com", mapname);
		try {
			resp.parse();
		} catch (SAMLParseException e1) {
			e1.printStackTrace();
			fail("Cannot parse correct NameIDMappingResponse");
		}
		assertTrue(true);

		try {

			resp.sign(privKey1, issuerCert1);
		} catch (Exception e) {
			e.printStackTrace();
			fail("Cannot sign NameIDMappingResponse");
		}

		assertTrue(resp.isSigned());
		try {
			assertTrue(resp.isCorrectlySigned(issuerCert1[0].getPublicKey()));
		} catch (DSigException e) {
			e.printStackTrace();
			fail("Cannot check NameIDMappingResponse signature");
		}

	}

}
