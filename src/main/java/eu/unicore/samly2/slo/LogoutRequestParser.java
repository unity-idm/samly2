/*
 * Copyright (c) 2019 Bixbit - Krzysztof Benedyczak. All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.samly2.slo;

import java.security.PrivateKey;

import org.w3c.dom.Document;

import eu.unicore.samly2.SAMLUtils;
import eu.unicore.samly2.validators.LogoutRequestValidator;
import eu.unicore.security.enc.EncryptionUtil;
import xmlbeans.org.oasis.saml2.assertion.EncryptedElementType;
import xmlbeans.org.oasis.saml2.assertion.NameIDType;
import xmlbeans.org.oasis.saml2.protocol.LogoutRequestDocument;
import xmlbeans.org.oasis.saml2.protocol.LogoutRequestType;

/**
 * Parses raw XML request, validates it and creates {@link ParsedLogoutRequest}. 
 */
public class LogoutRequestParser
{
	private final LogoutRequestValidator validator;
	private final EncryptionUtil encryptionEngine = new EncryptionUtil();
	private final PrivateKey decryptKey;

	public LogoutRequestParser(LogoutRequestValidator validator, PrivateKey decryptKey)
	{
		this.validator = validator;
		this.decryptKey = decryptKey;
	}
	
	public ParsedLogoutRequest parseRequest(LogoutRequestDocument logoutRequestDoc) throws Exception
	{
		validator.validate(logoutRequestDoc);
		LogoutRequestType logoutRequest = logoutRequestDoc.getLogoutRequest();
		
		NameIDType issuer = logoutRequest.getIssuer();
		NameIDType subject = parseSubject(logoutRequest);
		
		return new ParsedLogoutRequest(subject, issuer);
	}
	
	private NameIDType parseSubject(LogoutRequestType logoutRequest) throws Exception
	{
		return logoutRequest.getNameID() != null ? 
			logoutRequest.getNameID() : parseEncryptedSubject(logoutRequest);
	}
	
	private NameIDType parseEncryptedSubject(LogoutRequestType logoutRequest) throws Exception
	{
		EncryptedElementType encryptedID = logoutRequest.getEncryptedID();
		Document toDec = SAMLUtils.getDOM(encryptedID);
		Document decrypted = encryptionEngine.decrypt(toDec, decryptKey);
		return NameIDType.Factory.parse(decrypted.getDocumentElement());
	}
}
