package eu.unicore.samly2;

import java.util.Calendar;
import java.util.Date;

import org.apache.xmlbeans.XmlObject;

import xmlbeans.org.oasis.saml2.assertion.AssertionDocument;
import xmlbeans.org.oasis.saml2.assertion.AudienceRestrictionType;
import xmlbeans.org.oasis.saml2.assertion.AuthnContextType;
import xmlbeans.org.oasis.saml2.assertion.AuthnStatementType;
import eu.emi.security.authn.x509.impl.X500NameUtils;
import eu.unicore.samly2.assertion.Assertion;
import eu.unicore.samly2.assertion.AssertionParser;
import eu.unicore.samly2.elements.NameID;
import eu.unicore.samly2.elements.SAMLAttribute;
import eu.unicore.samly2.exceptions.SAMLValidationException;
import eu.unicore.samly2.proto.AssertionResponse;
import eu.unicore.samly2.trust.ResponseTrustCheckResult;
import eu.unicore.samly2.trust.SimpleTrustChecker;
import eu.unicore.samly2.trust.StrictSamlTrustChecker;
import eu.unicore.samly2.trust.DsigSamlTrustCheckerBase.CheckingMode;
import eu.unicore.security.dsig.TestBase;

/**
 * Tests {@link Assertion} and {@link AssertionParser} classes.
 * @author K. Benedyczak
 */
public class AssertionTest extends TestBase {
	private String subject1 = "C=PL,ST=Kujawsko-Pomorskie,L=Torun,O=UW,OU=ICM,CN=Krzysztof Benedyczak,1.2.840.113549.1.9.1=#1610676f6c6269406d61742e756d6b2e706c";

	public void testAssertionResp() throws SAMLValidationException {
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

		//in the default mode should require signed assertion always
		StrictSamlTrustChecker checker = new StrictSamlTrustChecker();
		checker.addTrustedIssuer(issuerDN1, SAMLConstants.NFORMAT_DN, issuerCert1[0].getPublicKey());

		ResponseTrustCheckResult checkTrust = checker.checkTrust(resp.getXMLBeanDoc(), resp.getXMLBean());
		assertTrue(checkTrust.isTrustEstablished());
		try
		{
	
			checker.checkTrust(as.getXMLBeanDoc(), checkTrust);
			fail("Should fail on unsigned assertion");
		} catch (SAMLValidationException e)
		{
			//OK
		}
		
		//in lax mode signed response should be enough
		StrictSamlTrustChecker checker2 = new StrictSamlTrustChecker(CheckingMode.REQUIRE_SIGNED_RESPONSE_OR_ASSERTION);
		checker2.addTrustedIssuer(issuerDN1, SAMLConstants.NFORMAT_DN, issuerCert1[0].getPublicKey());
		ResponseTrustCheckResult checkTrust2 = checker2.checkTrust(resp.getXMLBeanDoc(), resp.getXMLBean());
		assertTrue(checkTrust2.isTrustEstablished());
		checker2.checkTrust(as.getXMLBeanDoc(), checkTrust2);
	}

	public void testOptionalSignature() throws SAMLValidationException {
		NameID issuer = new NameID(issuerDN1, SAMLConstants.NFORMAT_DN);

		AssertionResponse resp = new AssertionResponse(issuer.getXBean(), "1234");
		Assertion as = new Assertion();
		as.addAttribute(new SAMLAttribute("a", "b"));
		resp.addAssertion(as);

		SimpleTrustChecker checker = new SimpleTrustChecker(issuerCert1[0], true);
		ResponseTrustCheckResult checkTrust = checker.checkTrust(resp.getXMLBeanDoc(), resp.getXMLBean());
		assertFalse(checkTrust.isTrustEstablished());
		checker.checkTrust(as.getXMLBeanDoc(), checkTrust);
		
		SimpleTrustChecker checker2 = new SimpleTrustChecker(issuerCert1[0], false);
		ResponseTrustCheckResult checkTrust2 = checker2.checkTrust(resp.getXMLBeanDoc(), resp.getXMLBean());
		assertFalse(checkTrust2.isTrustEstablished());
		try
		{
			checker2.checkTrust(as.getXMLBeanDoc(), checkTrust2);
			fail("Should fail on unsigned assertion");
		} catch (SAMLValidationException e)
		{
			//OK
		}
	}
	
	public void testAssertionParser()
	{
		AssertionParser assertion;
		try {
			AssertionDocument adoc = create(true);
			assertion = new AssertionParser(adoc);
		} catch (Exception e) {
			e.printStackTrace();
			fail("Cannot create assertion: " + e);
			return;
		}
		
		assertEquals(new Date(1000), assertion.getNotBefore());
		assertEquals(new Date(4500), assertion.getNotOnOrAfter());
		assertNotNull(assertion.getXMLBean());
		assertNotNull(assertion.getXMLBeanDoc());
		//JDK uses GMT by default, not UTC
		assertEquals("GMT", assertion.getXMLBean().getIssueInstant().getTimeZone().getID());
		assertEquals("foo", assertion.getXMLBean().getIssuer().getStringValue());
		assertEquals(SAMLConstants.NFORMAT_ENTITY, assertion.getXMLBean().getIssuer().getFormat());
		assertTrue(X500NameUtils.equal(subject1, assertion.getXMLBean().getSubject().getNameID().getStringValue()));
		assertEquals(SAMLConstants.NFORMAT_DN, assertion.getXMLBean().getSubject().getNameID().getFormat());
		assertEquals(18, assertion.getProxyRestriction());
		AudienceRestrictionType audienceRestrictionArray = assertion.getXMLBean().
				getConditions().getAudienceRestrictionArray(0);
		assertEquals("unicore.eu", audienceRestrictionArray.getAudienceArray()[0]);

		assertEquals(issuerCert2[0], assertion.getSubjectFromConfirmation()[0]);
		assertEquals(issuerCert1[0], assertion.getIssuerFromSignature()[0]);
		
		
		String value1 = (assertion.getXMLBean().getConditions().getConditionArray(0)).getDomNode()
				.getChildNodes().item(0).getChildNodes().item(0).getNodeValue();
		assertEquals("empty", value1);

		AuthnStatementType[] authStatements = assertion.getXMLBean().getAuthnStatementArray();
		assertEquals(authStatements.length, 1);

		assertEquals(1, assertion.getXMLBean().sizeOfAttributeStatementArray());
		assertEquals(2, assertion.getXMLBean().getAttributeStatementArray(0).sizeOfAttributeArray());

		assertTrue(assertion.isSigned());
		
		StrictSamlTrustChecker checker = new StrictSamlTrustChecker();
		checker.addTrustedIssuer("foo", SAMLConstants.NFORMAT_ENTITY, issuerCert1[0].getPublicKey());
		try
		{
			checker.checkTrust(assertion.getXMLBeanDoc());
		} catch (SAMLValidationException e)
		{
			e.printStackTrace();
			fail("Signature verification failed " + e);
		}
	}
	
	private AssertionDocument create(boolean sign) throws Exception
	{
		Assertion assertion = new Assertion();
		assertion.setIssuer("foo", SAMLConstants.NFORMAT_ENTITY);
		assertion.setX509Subject(subject1);
		assertion.setTimeConditions(new Date(1000), new Date(4500));
		assertion.setProxyRestriction(18);
		assertion.setAudienceRestriction(new String[] { "unicore.eu" });
		assertion.setHolderOfKeyConfirmation(issuerCert2);
		SAMLAttribute at = new SAMLAttribute("at1", SAMLConstants.AFORMAT_URI);
		at.addStringAttributeValue("val1");
		assertion.addAttribute(at);
		assertion.addAttribute(at);
		AuthnContextType ctx = AuthnContextType.Factory.newInstance();
		ctx.setAuthnContextClassRef("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport");
		assertion.addAuthStatement(Calendar.getInstance(), ctx);

		XmlObject cXml = XmlObject.Factory.parse(
				"<Conditions xmlns=\"urn:oasis:names:tc:SAML:2.0:assertion\">empty</Conditions>");
		assertion.addCustomCondition(cXml);
		
		if (sign)
			assertion.sign(privKey1, issuerCert1);
		
		return assertion.getXMLBeanDoc();
	}
}
