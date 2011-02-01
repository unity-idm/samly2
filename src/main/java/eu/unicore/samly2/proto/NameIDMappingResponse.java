/*
 * Copyright (c) 2007, 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on Sep 25, 2007
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.samly2.proto;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

import org.apache.xmlbeans.XmlException;
import org.apache.xmlbeans.XmlObject;
import org.w3c.dom.Document;

import eu.unicore.samly2.elements.NameID;
import eu.unicore.samly2.exceptions.SAMLParseException;
import eu.unicore.samly2.exceptions.SAMLProtocolException;
import eu.unicore.security.dsig.DSigException;

import xmlbeans.org.oasis.saml2.protocol.ExtensionsType;
import xmlbeans.org.oasis.saml2.protocol.NameIDMappingResponseDocument;
import xmlbeans.org.oasis.saml2.protocol.NameIDMappingResponseType;

/**
 * @author K. Benedyczak
 */
public class NameIDMappingResponse extends AbstractStatusResponse {
	private NameIDMappingResponseType respXml;
	private NameIDMappingResponseDocument xbdoc;

	public NameIDMappingResponse(NameIDMappingResponseDocument src)
			throws SAMLParseException {
		super(src.getNameIDMappingResponse());
		xbdoc = src;
		respXml = src.getNameIDMappingResponse();
	}

	public NameIDMappingResponse(NameID issuer, String inResponseTo,
			NameID mapped) {
		xbdoc = NameIDMappingResponseDocument.Factory.newInstance();
		respXml = xbdoc.addNewNameIDMappingResponse();
		init(respXml, issuer, inResponseTo);
		respXml.setNameID(mapped.getXBean());
		respXml.setStatus(getOKStatus());
	}

	public NameIDMappingResponse(NameID issuer, String inResponseTo,
			SAMLProtocolException error) {
		xbdoc = NameIDMappingResponseDocument.Factory.newInstance();
		respXml = xbdoc.addNewNameIDMappingResponse();
		init(respXml, issuer, inResponseTo);
		// ughhh -> what to do?? SAML requires nameID in response always,
		// even when there is an error!
		respXml.addNewNameID().setNil();
		respXml.setStatus(getErrorStatus(error));
	}

	public void setExtensions(XmlObject val) {
		ExtensionsType exts = respXml.getExtensions();
		if (exts == null)
			exts = respXml.addNewExtensions();
		exts.set(val);
	}

	public NameIDMappingResponseDocument getDoc() {
		return xbdoc;
	}

	@Override
	public void parse() throws SAMLParseException {
		super.parse();
		if (respXml.getEncryptedID() != null)
			throw new SAMLParseException(
					"Unsupported encrypted nameID received");
		if (respXml.getNameID() == null)
			throw new SAMLParseException("No nameID in response");
	}

	@Override
	public boolean isCorrectlySigned(PublicKey key) throws DSigException {
		return isCorrectlySigned(key, (Document) xbdoc.getDomNode());
	}

	@Override
	public void sign(PrivateKey pk, X509Certificate[] cert)
			throws DSigException {
		Document doc = signInt(pk, cert);
		try {
			xbdoc = NameIDMappingResponseDocument.Factory.parse(doc);
			xmlResp = xbdoc.getNameIDMappingResponse();
			respXml = xbdoc.getNameIDMappingResponse();

		} catch (XmlException e) {
			throw new DSigException("Parsing signed document failed", e);
		}
	}
}
