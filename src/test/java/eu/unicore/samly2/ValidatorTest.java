package eu.unicore.samly2;

import eu.unicore.samly2.SAMLConstants;
import eu.unicore.samly2.elements.NameID;
import eu.unicore.samly2.elements.SAMLAttribute;
import eu.unicore.samly2.elements.Subject;
import eu.unicore.samly2.exceptions.SAMLServerException;
import eu.unicore.samly2.proto.AttributeQuery;
import eu.unicore.samly2.trust.StrictSamlTrustChecker;
import eu.unicore.samly2.validators.AttributeQueryValidator;
import eu.unicore.samly2.validators.ReplayAttackChecker;
import eu.unicore.security.dsig.DSigException;
import eu.unicore.security.dsig.TestBase;

/**
 * Tests validators
 * @author K. Benedyczak
 */
public class ValidatorTest extends TestBase {

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
}
