/*
 * Copyright (c) 2007, 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on Aug 21, 2007
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package pl.edu.icm.samly2;

import javax.xml.namespace.QName;

/**
 * @author K. Benedyczak
 */
public class SAMLConstants
{
	private static final String SAML_P = "urn:oasis:names:tc:SAML:2.0:";
	private static final String STAT_P = SAML_P + "status:";
	private static final String NAME_FORMAT_P = 
		"urn:oasis:names:tc:SAML:1.1:nameid-format:";
	
	public static final String NFORMAT_UNSPEC = NAME_FORMAT_P + "unspecified";
	public static final String NFORMAT_DN = NAME_FORMAT_P + "X509SubjectName";
	public static final String NFORMAT_ENC = NAME_FORMAT_P + "encrypted";
	public static final String NFORMAT_ENTITY = NAME_FORMAT_P + "entity";
	
	public static final String AFORMAT_BASIC = SAML_P + "attrname-format:basic";
	public static final String AFORMAT_URI = SAML_P + "attrname-format:uri";
	
	public static final String STATUS_OK = STAT_P + "Success";
	public static final String STATUS_REQUESTER = STAT_P + "Requester";
	public static final String STATUS_RESPONDER = STAT_P + "Responder";
	public static final String STATUS_VERSION_MISMATCH = STAT_P + "VersionMismatch";
	
	public static final String STATUS2_UNKNOWN_PRINCIPIAL = STAT_P + "UnknownPrincipial";
	public static final String STATUS2_AUTHN_FAILED = STAT_P + "AuthnFailed";
	public static final String STATUS2_REQUEST_DENIED = STAT_P + "RequestDenied";	
	public static final String STATUS2_INVALID_ATTR = STAT_P + "InvalidAttrNameOrValue";
	public static final String STATUS2_REQUEST_UNSUPP = STAT_P + "RequestUnsupported";
	public static final String STATUS2_INVALID_NAMEID_POLICY = STAT_P + "InvalidNameIDPolicy";
	public static final String STATUS2_VER_TOO_HIGH = STAT_P + "RequestVersionTooHigh";
	public static final String STATUS2_VER_TOO_LOW = STAT_P + "RequestVersionTooLow";

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
}
