/*
 * Copyright (c) 2007, 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on Aug 21, 2007
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.samly2;

import javax.xml.namespace.QName;

/**
 * @author K. Benedyczak
 */
public class SAMLConstants
{
	private static final String SAML_P = "urn:oasis:names:tc:SAML:2.0:";
	public static final String STAT_P = SAML_P + "status:";
	private static final String NAME_FORMAT11_P = 
		"urn:oasis:names:tc:SAML:1.1:nameid-format:";
	private static final String NAME_FORMAT20_P = 
		"urn:oasis:names:tc:SAML:2.0:nameid-format:";

	public static final String ASSERTION_NS = SAML_P + "assertion";
	public static final String PROTOCOL_NS = SAML_P + "protocol";
	
	
	public static final String NFORMAT_UNSPEC = NAME_FORMAT11_P + "unspecified";
	public static final String NFORMAT_EMAIL = NAME_FORMAT11_P + "emailAddress";
	public static final String NFORMAT_DN = NAME_FORMAT11_P + "X509SubjectName";
	public static final String NFORMAT_WDQN = NAME_FORMAT11_P + "WindowsDomainQualifiedName";
	public static final String NFORMAT_ENC = NAME_FORMAT20_P + "encrypted";
	public static final String NFORMAT_KERBEROS = NAME_FORMAT20_P + "kerberos";
	public static final String NFORMAT_ENTITY = NAME_FORMAT20_P + "entity";
	public static final String NFORMAT_PERSISTENT = NAME_FORMAT20_P + "persistent";
	public static final String NFORMAT_TRANSIENT = NAME_FORMAT20_P + "transient";
	
	public static final String AFORMAT_BASIC = SAML_P + "attrname-format:basic";
	public static final String AFORMAT_URI = SAML_P + "attrname-format:uri";
	public static final String AFORMAT_UNSPEC = SAML_P + "attrname-format:unspecified";
	
	public static final String CONFIRMATION_SENDER_VOUCHES = SAML_P + "cm:sender-vouches";
	public static final String CONFIRMATION_HOLDER_OF_KEY = SAML_P + "cm:holder-of-key";
	public static final String CONFIRMATION_BEARER = SAML_P + "cm:bearer";

	public static final String SAML2_VERSION = "2.0";
	
	//the rest is from different SAML profiles
	
	public static final QName XACMLDT = new QName(
			"urn:oasis:names:tc:SAML:2.0:profiles:attribute:XACML", 
			"DataType");
	public static final String XACMLDT_STRING = "http://www.w3.org/2001/XMLSchema#string";
	public static final String XACMLDT_SCOPED_STRING = "urn:SAML:voprofile:ScopedAttribute";

	public static final String SCOPE_TYPE_SIMPLE = "urn:SAML:voprofile:SimpleScopedString";
	public static final String SCOPE_TYPE_ATTRIBUTE = "urn:SAML:voprofile:ScopedValue";
	public static final String SCOPE_TYPE_NONE = "urn:SAML:voprofile:NonScopedValue";
	public static final QName SCOPE_TYPE_XMLATTRIBUTE = new QName("urn:vo:SAML:2.0:attribute:ext", "scopeType");
	public static final QName ATTRIBUTE_SCOPE_XMLATTRIBUTE = new QName("urn:vo:SAML:2.0:attribute:ext", "attributeScope");
	
	public static final String SAML_AC_UNSPEC = "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified";
	
	//standard SAML POST binding name - SAML request is encoded in this field
	public static final String REQ_SAML_REQUEST = "SAMLRequest";
	//relay state
	public static final String RELAY_STATE = "RelayState";

	
	public static enum AuthNClasses {NONE, TLS};
	
	public enum Status 
	{
		STATUS_OK(STAT_P + "Success"),
		STATUS_REQUESTER(STAT_P + "Requester"),
		STATUS_RESPONDER(STAT_P + "Responder"),
		STATUS_VERSION_MISMATCH(STAT_P + "VersionMismatch");
		
		private String name;
		
		Status(String s)
		{
			this.name = s;
		}
		
		public String toString()
		{
			return name;
		}
		
		public static Status fromString(String arg)
		{
			for (Status value: Status.values())
				if (arg.equals(value.name))
					return value;
			throw new IllegalArgumentException("Unknown status " + arg);
		}
	}
	
	public enum SubStatus 
	{
		STATUS2_UNKNOWN_PRINCIPIAL(STAT_P + "UnknownPrincipial"),
		STATUS2_AUTHN_FAILED(STAT_P + "AuthnFailed"),
		STATUS2_REQUEST_DENIED(STAT_P + "RequestDenied"),	
		STATUS2_INVALID_ATTR(STAT_P + "InvalidAttrNameOrValue"),
		STATUS2_REQUEST_UNSUPP(STAT_P + "RequestUnsupported"),
		STATUS2_INVALID_NAMEID_POLICY(STAT_P + "InvalidNameIDPolicy"),
		STATUS2_VER_TOO_HIGH(STAT_P + "RequestVersionTooHigh"),
		STATUS2_VER_TOO_LOW(STAT_P + "RequestVersionTooLow");
		
		private String name;
		
		SubStatus(String s)
		{
			this.name = s;
		}
		
		public String toString()
		{
			return name;
		}
		
		public static SubStatus fromString(String arg)
		{
			for (SubStatus value: SubStatus.values())
				if (arg.equals(value.name))
					return value;
			throw new IllegalArgumentException("Unknown substatus " + arg);
		}
	}

}
