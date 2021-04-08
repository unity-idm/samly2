/*
 * Copyright (c) 2021 Bixbit - Krzysztof Benedyczak. All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.samly2.messages;

import org.apache.xmlbeans.XmlObject;

import eu.unicore.samly2.SAMLBindings;

public class SAMLMessage<T extends XmlObject>
{
	public final SAMLVerifiableElement verifiableMessage;
	public final String relayState;
	public final SAMLBindings binding;
	public final T messageDocument;
	
	public SAMLMessage(SAMLVerifiableElement verifiableMessage, String relayState, SAMLBindings binding,
			T messageDocument)
	{
		this.verifiableMessage = verifiableMessage;
		this.relayState = relayState;
		this.binding = binding;
		this.messageDocument = messageDocument;
	}
}
