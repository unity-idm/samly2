/*
 * Copyright (c) 2007, 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on Aug 17, 2007
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.samly2.webservice;

import jakarta.jws.WebMethod;
import jakarta.jws.WebResult;
import jakarta.jws.WebService;
import jakarta.jws.soap.SOAPBinding;
import xmlbeans.org.oasis.saml2.protocol.LogoutRequestDocument;
import xmlbeans.org.oasis.saml2.protocol.LogoutResponseDocument;

/**
 * @author K. Benedyczak
 */
@WebService(name="SingleLogoutService", 
	targetNamespace="urn:oasis:names:tc:SAML:2.0:protocol")
@SOAPBinding(parameterStyle=SOAPBinding.ParameterStyle.BARE)
public interface SAMLLogoutInterface
{
	@WebMethod(action="http://www.oasis-open.org/committees/security", operationName="LogoutRequest")
	@WebResult(name="LogoutResponse")
	public LogoutResponseDocument logoutRequest(LogoutRequestDocument reqDoc);
}
