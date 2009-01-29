/*
 * Copyright (c) 2007, 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on Sep 25, 2007
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.samly2.proto;

import eu.unicore.samly2.elements.NameID;
import eu.unicore.samly2.elements.Subject;
import eu.unicore.samly2.exceptions.SAMLProtocolException;
import eu.unicore.samly2.exceptions.SAMLRequestException;
import xmlbeans.org.oasis.saml2.assertion.SubjectType;
import xmlbeans.org.oasis.saml2.protocol.SubjectQueryAbstractType;

/**
 * @author K. Benedyczak
 */
public abstract class AbstractSubjectQuery extends AbstractRequest
{
	protected SubjectQueryAbstractType subXmlReq;
	
	protected AbstractSubjectQuery()
	{
	}
	
	protected AbstractSubjectQuery(SubjectQueryAbstractType src) 
	{
		super(src);
		subXmlReq = (SubjectQueryAbstractType)xmlReq;
	}

	protected void init(SubjectQueryAbstractType src, NameID issuer,
			Subject subject)
	{
		super.init(src, issuer);
		subXmlReq = (SubjectQueryAbstractType)xmlReq;
		subXmlReq.setSubject(subject.getXBean());
	}

	public void parse() throws SAMLProtocolException
	{
		super.parse();
		SubjectType subject = subXmlReq.getSubject();
		if (subject == null)
			throw new SAMLRequestException(null, "Subject can't be empty");
	}

	public Subject getSubject()
	{
		return new Subject(subXmlReq.getSubject());
	}
}