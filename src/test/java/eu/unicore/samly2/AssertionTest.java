package eu.unicore.samly2;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import java.io.File;
import java.util.Date;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import javax.xml.datatype.DatatypeFactory;

import org.junit.Test;
import org.w3c.dom.Document;

import eu.unicore.samly2.assertion.AssertionParser;
import eu.unicore.samly2.jaxb.saml2.assertion.Assertion;
import eu.unicore.samly2.jaxb.saml2.assertion.AssertionType;
import eu.unicore.samly2.jaxb.saml2.assertion.Conditions;
import eu.unicore.samly2.jaxb.saml2.assertion.ConditionsType;
import eu.unicore.samly2.jaxb.saml2.assertion.Issuer;
import eu.unicore.samly2.jaxb.saml2.assertion.NameIDType;
import eu.unicore.security.dsig.DigSignatureUtil;
import eu.unicore.security.dsig.TestBase;

/**
 * Tests {@link Assertion} and {@link AssertionParser} classes.
 * @author K. Benedyczak
 */
public class AssertionTest extends TestBase {
	//private String subject1 = "C=PL,ST=Kujawsko-Pomorskie,L=Torun,O=UW,OU=ICM,CN=Krzysztof Benedyczak,1.2.840.113549.1.9.1=#1610676f6c6269406d61742e756d6b2e706c";

	@Test
	public void parsedDocumentShouldBeNotChangedAfterConversionToDOM() throws JAXBException
	{
		JAXBContext context = JAXBUtils.getContext();
		String path = "src/test/resources/assert.xml";
		
		Unmarshaller unmarshaller = context.createUnmarshaller();
		Assertion loaded = (Assertion)unmarshaller.unmarshal(new File(path));

		AssertionParser parser = new AssertionParser(loaded);
		Document asDOM = parser.getAsDOM();
		String domAsString = DigSignatureUtil.dumpDOMToString(asDOM);
		System.out.println(domAsString);
	}
	
	
	public void testAssertionParser()
	{
		AssertionParser assertion;
		try {
			JAXBElement<AssertionType> adoc = create(true);
			assertion = new AssertionParser(adoc);
		} catch (Exception e) {
			e.printStackTrace();
			fail("Cannot parse assertion: " + e);
			return;
		}
		
		assertThat(assertion.getNotBefore(), is(new Date(1000)));
		assertThat(assertion.getNotOnOrAfter(), is(new Date(4500)));
		assertThat(assertion.getJAXBObject(), is(notNullValue()));

		/*
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
		*/
	}
	
	private JAXBElement<AssertionType> create(boolean sign) throws Exception
	{
		AssertionType assertionType = new AssertionType();
		NameIDType nameId = new NameIDType();
		nameId.setFormat(SAMLConstants.NFORMAT_ENTITY);
		nameId.setValue("foo");
		assertionType.setIssuer(new Issuer(nameId));
		ConditionsType conditions = new ConditionsType();
		DatatypeFactory dataFactory = DatatypeFactory.newInstance();
		conditions.setNotBefore(dataFactory.newXMLGregorianCalendar("20101022T101010"));
		conditions.setNotOnOrAfter(dataFactory.newXMLGregorianCalendar("20501022T101010"));
		assertionType.setConditions(new Conditions(conditions));
		
	//	JAXBContext context = JAXBContext.newInstance(Assertion.class);
		//context.createUnmarshaller().
		return null;
		
		/*
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
		*/
	}
}
