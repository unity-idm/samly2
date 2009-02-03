/*
 * Copyright (c) 2007, 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on Feb 27, 2008
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.security.dsig;

import java.io.FileInputStream;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.xml.security.signature.XMLSignatureInput;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.Constants;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import com.sun.org.apache.xpath.internal.XPathAPI;

/**
 * @author K. Benedyczak
 */
public class StandaloneCanonizer
{
	private DocumentBuilder documentBuilder;
	
	public StandaloneCanonizer() throws Exception
	{
		DocumentBuilderFactory dfactory = DocumentBuilderFactory.newInstance();
		dfactory.setNamespaceAware(true);
		dfactory.setValidating(false);
		documentBuilder = dfactory.newDocumentBuilder();		
	}
	
	/**
	 * @param args
	 */
	public static void main(String[] args)
	{
		boolean doEnvTr = false;
		if (args.length > 0)
		{
			if (args[0].equals("-e"))
				doEnvTr = true;
		}
		try
		{
			StandaloneCanonizer instance = new StandaloneCanonizer();
			
			Document doc = instance.readDoc(null);
			String res = instance.fireCanon(doc, doEnvTr);
			System.out.println(res);
		} catch (Exception e)
		{
			e.printStackTrace();
		}
		
	}

	
	private Document readDoc(String file) throws Exception
	{
		Document inputDoc = documentBuilder.parse(file == null ?
				System.in : new FileInputStream(file));
		return inputDoc;
	}

	public static Element createDSctx(Document doc, String prefix,
		String namespace)
	{
		Element ctx = doc.createElementNS(null, "namespaceContext");
		ctx.setAttributeNS(Constants.NamespaceSpecNS, "xmlns:" + prefix, namespace);
		return ctx;
	}


	public String fireCanon(Document inputDoc, boolean envSigTr) throws Exception
	{
		org.apache.xml.security.Init.init();
		XMLSignatureInput signatureInput = new XMLSignatureInput((Node) inputDoc);
		Document transformDoc = documentBuilder.newDocument();

		XMLSignatureInput result;
		if (envSigTr)
		{
			Element nscontext = createDSctx(inputDoc, "ds", 
					Constants.SignatureSpecNS);
			Element transformsElement = (Element) XPathAPI.selectSingleNode(
					inputDoc, "//ds:Transforms", nscontext);
			Transforms transforms = new Transforms(transformsElement, 
					"memory://");
			result = transforms.performTransforms(signatureInput);
		} else
		{
			Transforms c14nTrans = new Transforms(transformDoc);
			transformDoc.appendChild(c14nTrans.getElement());
			c14nTrans.addTransform(Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);
			result = c14nTrans.performTransforms(signatureInput);			
		}
		
		byte outputBytes[] = result.getBytes();
		return new String(outputBytes);
	}
}
