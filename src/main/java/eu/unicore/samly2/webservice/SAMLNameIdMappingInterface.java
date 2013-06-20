/*
 * Copyright (c) 2007, 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on Aug 17, 2007
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.samly2.webservice;

import javax.jws.WebMethod;
import javax.jws.WebService;
import javax.jws.soap.SOAPBinding;

import xmlbeans.org.oasis.saml2.protocol.NameIDMappingRequestDocument;
import xmlbeans.org.oasis.saml2.protocol.NameIDMappingResponseDocument;

@WebService(name="NameIDMappingRequestService", 
	targetNamespace="urn:oasis:names:tc:SAML:2.0:protocol")
@SOAPBinding(parameterStyle=SOAPBinding.ParameterStyle.BARE)
public interface SAMLNameIdMappingInterface
{
	@WebMethod(action="http://www.oasis-open.org/committees/security", operationName="NameIDMappingRequest")
	public NameIDMappingResponseDocument nameIDMappingRequest(NameIDMappingRequestDocument request); 
}
