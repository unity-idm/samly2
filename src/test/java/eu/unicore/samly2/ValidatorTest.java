package eu.unicore.samly2;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;
import static org.junit.Assert.*;

import org.junit.Test;

import xmlbeans.org.oasis.saml2.assertion.SubjectType;
import eu.unicore.samly2.assertion.Assertion;
import eu.unicore.samly2.elements.NameID;
import eu.unicore.samly2.elements.SAMLAttribute;
import eu.unicore.samly2.elements.Subject;
import eu.unicore.samly2.exceptions.SAMLServerException;
import eu.unicore.samly2.proto.AttributeQuery;
import eu.unicore.samly2.trust.AcceptingSamlTrustChecker;
import eu.unicore.samly2.trust.SamlTrustChecker;
import eu.unicore.samly2.trust.StrictSamlTrustChecker;
import eu.unicore.samly2.validators.AssertionValidator;
import eu.unicore.samly2.validators.AttributeQueryValidator;
import eu.unicore.samly2.validators.ReplayAttackChecker;
import eu.unicore.security.dsig.DSigException;
import eu.unicore.security.dsig.TestBase;

public class ValidatorTest extends TestBase {

	@Test
	public void testAttrQuery() throws SAMLServerException {
		String subject = "C=PL,ST=Kujawsko-Pomorskie,L=Torun,O=UW,OU=ICM,CN=Krzysztof Benedyczak,1.2.840.113549.1.9.1=#1610676f6c6269406d61742e756d6b2e706c";

		NameID issuer = new NameID(issuerDN1, SAMLConstants.NFORMAT_DN);
		Subject sub = new Subject(subject, SAMLConstants.NFORMAT_DN);

		AttributeQuery query = new AttributeQuery(issuer.getXBean(), sub.getXBean());
		query.getXMLBean().setDestination("https://somehost:443/foo/bar");
		
		SAMLAttribute at = new SAMLAttribute("at1", SAMLConstants.AFORMAT_URI);
		query.setAttributes(new SAMLAttribute[]{at});
		try {
			query.sign(privKey1, issuerCert1);
		} catch (DSigException e) {
			e.printStackTrace();
			fail("Cannot sign AttributeQuery");
		}
		
		StrictSamlTrustChecker checker = new StrictSamlTrustChecker();
		checker.addTrustedIssuer(issuerDN1, SAMLConstants.NFORMAT_DN, issuerCert1[0].getPublicKey());
		AttributeQueryValidator validator = new AttributeQueryValidator("https://somehost/foo/bar", 
				checker, 10000, new ReplayAttackChecker());
		validator.validate(query.getXMLBeanDoc());
	}
	
	@Test
	public void emptySubjectAllowed() throws SAMLServerException {
		Assertion a = new Assertion();
		SubjectType subject = SubjectType.Factory.newInstance();
		a.getXMLBean().setSubject(subject);
		a.setIssuer(issuerDN1, SAMLConstants.NFORMAT_DN);
		SamlTrustChecker checker = new AcceptingSamlTrustChecker();
		AssertionValidator validator = new AssertionValidator("https://somehost/foo/bar", 
				"", "", 1000L, checker, null);

		Throwable throwable = catchThrowable(() -> validator.validate(a.getXMLBeanDoc()));
		
		assertThat(throwable).isNull();
	}
}
