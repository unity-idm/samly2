/*
 * Copyright (c) 2007, 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on Aug 17, 2007
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.samly2.webservice;

import javax.jws.WebMethod;
import javax.jws.WebResult;
import javax.jws.WebService;
import javax.jws.soap.SOAPBinding;

import xmlbeans.org.oasis.saml2.protocol.AssertionIDRequestDocument;
import xmlbeans.org.oasis.saml2.protocol.AttributeQueryDocument;
import xmlbeans.org.oasis.saml2.protocol.AuthnQueryDocument;
import xmlbeans.org.oasis.saml2.protocol.AuthzDecisionQueryDocument;
import xmlbeans.org.oasis.saml2.protocol.ResponseDocument;

/**
 * @author K. Benedyczak
 */
@WebService(name="AssertionQueryService", 
	targetNamespace="urn:oasis:names:tc:SAML:2.0:protocol")
@SOAPBinding(parameterStyle=SOAPBinding.ParameterStyle.BARE)
public interface SAMLQueryInterface
{
	@WebMethod(action="http://www.oasis-open.org/committees/security", operationName="AttributeQuery")
	@WebResult(name="Response") 
	public ResponseDocument attributeQuery(AttributeQueryDocument query);

	
	
	/*
	 * Note that the following SAML operations are not anyhow used in UNICORE. 
	 */
	
	@WebMethod(action="http://www.oasis-open.org/committees/security", operationName="AssertionIDRequest")
	@WebResult(name="Response") 
	public ResponseDocument assertionIDRequest(AssertionIDRequestDocument query);

	@WebMethod(action="http://www.oasis-open.org/committees/security", operationName="AuthnQuery")
	@WebResult(name="Response") 
	public ResponseDocument authnQuery(AuthnQueryDocument query);
	
	@WebMethod(action="http://www.oasis-open.org/committees/security", operationName="AuthzDecisionQuery")
	@WebResult(name="Response") 
	public ResponseDocument authzDecisionQuery(AuthzDecisionQueryDocument query);
	
}
