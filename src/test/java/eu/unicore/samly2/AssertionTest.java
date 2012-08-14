package eu.unicore.samly2;

import java.io.File;
import java.util.Calendar;
import java.util.Date;

import org.apache.xmlbeans.XmlException;
import org.apache.xmlbeans.XmlObject;

import xmlbeans.org.oasis.saml2.assertion.AssertionDocument;
import xmlbeans.org.oasis.saml2.assertion.AssertionType;
import xmlbeans.org.oasis.saml2.assertion.AudienceRestrictionType;
import xmlbeans.org.oasis.saml2.assertion.AuthnContextType;
import xmlbeans.org.oasis.saml2.assertion.AuthnStatementType;
import eu.unicore.samly2.SAMLConstants;
import eu.unicore.samly2.assertion.Assertion;
import eu.unicore.samly2.elements.NameID;
import eu.unicore.samly2.elements.SAMLAttribute;
import eu.unicore.samly2.elements.Subject;
import eu.unicore.security.dsig.DSigException;
import eu.unicore.security.dsig.TestBase;

public class AssertionTest extends TestBase {
	private String subject1 = "C=PL,ST=Kujawsko-Pomorskie,L=Torun,O=UW,OU=ICM,CN=Krzysztof Benedyczak,1.2.840.113549.1.9.1=#1610676f6c6269406d61742e756d6b2e706c";
	private String subject2 = "C=PL,ST=Kujawsko-Pomorskie,L=Torun,O=UW,OU=ICM,CN=Piotr Piernik,1.2.840.113549.1.9.1=#1610676f6c6269406d61742e756d6b2e706c";

	public void testAssertion() {
		AssertionDocument adoc = null;
		Assertion assertion = null;
		adoc = AssertionDocument.Factory.newInstance();
		adoc.setAssertion(AssertionType.Factory.newInstance());
		NameID issuer = new NameID(issuerDN1, SAMLConstants.NFORMAT_DN);
		adoc.getAssertion().setIssuer(issuer.getXBean());

		try {
			assertion = new Assertion(adoc);

		} catch (Exception e) {
			e.printStackTrace();
			fail("Cannot create assertion from xml");
		}

		assertEquals(assertion.getIssuerDN(), issuerDN1);
		assertion.setX509Issuer(issuerDN2);
		assertEquals(assertion.getIssuerDN(), issuerDN2);

		Calendar old = assertion.getXML().getAssertion().getIssueInstant();
		assertion.updateIssueTime();
		assertNotSame(old, assertion.getXML().getAssertion().getIssueInstant());

		Subject sub = new Subject(subject1, SAMLConstants.NFORMAT_DN);
		assertion.setSubject(sub.getXBean());
		assertEquals(assertion.getSubjectDN(), subject1);

		assertion.getXML().getAssertion().unsetSubject();

		assertion.setX509Subject(subject2);
		assertEquals(assertion.getSubjectDN(), subject2);

		assertNull(assertion.getSubjectFromConfirmation());
		try {
			assertion.setSenderVouchesX509Confirmation(issuerCert2);
		} catch (Exception e) {

			e.printStackTrace();
			fail("Cannot set sender vouches confirmation");
		}
		assertEquals(issuerDN2, assertion.getSubjectFromConfirmation()[0]
				.getSubjectX500Principal().getName());

		Calendar cal = Calendar.getInstance();
		cal.add(Calendar.MONTH, -1);
		Date bdate = cal.getTime();
		cal.add(Calendar.MONTH, 2);
		Date adate = cal.getTime();
		assertion.setTimeConditions(bdate, adate);

		assertTrue(assertion.checkTimeConditions());
		assertEquals(bdate, assertion.getNotBefore());
		assertEquals(adate, assertion.getNotOnOrAfter());

		assertion.setAudienceRestriction(new String[] { "unicore.eu" });
		AudienceRestrictionType audienceRestrictionArray = assertion.getXML()
				.getAssertion().getConditions().getAudienceRestrictionArray(0);
		assertEquals("unicore.eu", audienceRestrictionArray.getAudienceArray()[0]);

		assertion.setProxyRestriction(2);
		assertEquals(2, assertion.getProxyRestriction());

		XmlObject cXml = null;
		try {
			cXml = XmlObject.Factory
					.parse("<Conditions xmlns=\"urn:oasis:names:tc:SAML:2.0:assertion\">empty</Conditions>");
		} catch (XmlException e) {
			e.printStackTrace();
			fail("Cannot parse xml");
		}
		assertion.addCustomCondition(cXml);
		String value1 = (assertion.getCustomConditions()[0]).getDomNode()
				.getChildNodes().item(0).getChildNodes().item(0).getNodeValue();
		String value2 = cXml.getDomNode().getChildNodes().item(0)
				.getChildNodes().item(0).getNodeValue();
		assertEquals(value1, value2);

		SAMLAttribute attr = new SAMLAttribute(
				"http://voms.forge.cnaf.infn.it/group",
				SAMLConstants.NFORMAT_UNSPEC);
		attr.addStringAttributeValue("test");

		AuthnContextType ctx = AuthnContextType.Factory.newInstance();
		ctx
				.setAuthnContextClassRef("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport");
		assertion.addAuthStatement(Calendar.getInstance(), ctx);
		AuthnStatementType[] authStatements = assertion.getAuthStatements();
		assertEquals(authStatements.length, 1);

	}

	public void testSign() {
		Assertion as = null;
		try {
			AssertionDocument doc = AssertionDocument.Factory.parse(new File(
					"src/test/resources/assert.xml"));
			as = new Assertion(doc);
		} catch (Exception e) {
			e.printStackTrace();
			fail("Cannot create assertion from xml");
		}
		assertNotNull(as);
		assertFalse(as.isSigned());
		try {
			as.sign(privKey1, issuerCert1);
		} catch (DSigException e) {
			e.printStackTrace();
			fail();
		}

		assertTrue(as.isSigned());
		try {
			assertTrue(as.isCorrectlySigned(issuerCert1[0].getPublicKey()));
		} catch (DSigException e) {
			e.printStackTrace();
			fail("Cannot check assertion signature");
		}

	}

}
