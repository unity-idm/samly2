package eu.unicore.samly2;

import java.util.Calendar;
import java.util.Date;

import org.apache.xmlbeans.XmlObject;

import xmlbeans.org.oasis.saml2.assertion.AssertionDocument;
import xmlbeans.org.oasis.saml2.assertion.AudienceRestrictionType;
import xmlbeans.org.oasis.saml2.assertion.AuthnContextType;
import xmlbeans.org.oasis.saml2.assertion.AuthnStatementType;
import eu.emi.security.authn.x509.impl.X500NameUtils;
import eu.unicore.samly2.SAMLConstants;
import eu.unicore.samly2.assertion.Assertion;
import eu.unicore.samly2.assertion.AssertionParser;
import eu.unicore.samly2.elements.SAMLAttribute;
import eu.unicore.samly2.exceptions.SAMLValidationException;
import eu.unicore.samly2.trust.StrictSamlTrustChecker;
import eu.unicore.security.dsig.TestBase;

/**
 * Tests {@link Assertion} and {@link AssertionParser} classes.
 * @author K. Benedyczak
 */
public class AssertionTest extends TestBase {
	private String subject1 = "C=PL,ST=Kujawsko-Pomorskie,L=Torun,O=UW,OU=ICM,CN=Krzysztof Benedyczak,1.2.840.113549.1.9.1=#1610676f6c6269406d61742e756d6b2e706c";

	
	public void testAssertionParser()
	{
		AssertionParser assertion;
		try {
			AssertionDocument adoc = create();
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
		checker.addTrustedIssuer("foo", issuerCert1[0].getPublicKey());
		try
		{
			checker.checkTrust(assertion.getXMLBeanDoc());
		} catch (SAMLValidationException e)
		{
			e.printStackTrace();
			fail("Signature verification failed " + e);
		}
	}
	
	private AssertionDocument create() throws Exception
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
		
		assertion.sign(privKey1, issuerCert1);
		
		return assertion.getXMLBeanDoc();
	}
}
