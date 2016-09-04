package eu.unicore.samly2;

import static org.junit.Assert.assertEquals;

import org.apache.xmlbeans.XmlObject;
import org.junit.Test;

import eu.unicore.samly2.elements.SAMLAttribute;

public class SAMLAttributeTest {

	@SuppressWarnings("deprecation")
	@Test
	public void testAttribute() {
		SAMLAttribute attr = new SAMLAttribute(
				"http://voms.forge.cnaf.infn.it/group",
				"urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified");
		attr.setFriendlyName("Telephone");
		attr.addStringAttributeValue("+1-888-555-1212");	
		attr.addScopedStringAttributeValue("test1", SAMLConstants.SCOPE_TYPE_SIMPLE);
		attr.addStringAttributeValue("test2");
		
		SAMLAttribute attr2=new SAMLAttribute(attr.getXBean());
		XmlObject attributeValueArray = attr2.getXBean().getAttributeValueArray(0);
		String value=attributeValueArray.getDomNode().getChildNodes().item(0).getNodeValue();
		assertEquals("+1-888-555-1212",value);
		
		attributeValueArray = attr2.getXBean().getAttributeValueArray(1);
		value=attributeValueArray.getDomNode().getChildNodes().item(0).getNodeValue();
		assertEquals("test1",value);
		
		attributeValueArray = attr2.getXBean().getAttributeValueArray(2);
		value=attributeValueArray.getDomNode().getChildNodes().item(0).getNodeValue();
		assertEquals("test2",value);
		
		assertEquals("Telephone",attr2.getFriendlyName());

	

	}
}
