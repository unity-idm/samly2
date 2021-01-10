/*
 * Copyright (c) 2007, 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on Feb 27, 2008
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.security.dsig;

import java.io.FileInputStream;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Collections;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.core.config.builder.api.AppenderComponentBuilder;
import org.apache.logging.log4j.core.config.builder.api.ConfigurationBuilder;
import org.apache.logging.log4j.core.config.builder.api.ConfigurationBuilderFactory;
import org.apache.logging.log4j.core.config.builder.api.LayoutComponentBuilder;
import org.apache.logging.log4j.core.config.builder.api.RootLoggerComponentBuilder;
import org.apache.logging.log4j.core.config.builder.impl.BuiltConfiguration;
import org.w3c.dom.Document;

import eu.unicore.samly2.assertion.AssertionParser;
import eu.unicore.samly2.trust.SamlTrustChecker;
import xmlbeans.org.oasis.saml2.assertion.AssertionDocument;


public class AssertionSignatureChecker
{
	private DocumentBuilder documentBuilder;

	public AssertionSignatureChecker() throws Exception
	{
		DocumentBuilderFactory dfactory = DocumentBuilderFactory.newInstance();
		dfactory.setNamespaceAware(true);
		dfactory.setValidating(false);
		documentBuilder = dfactory.newDocumentBuilder();		
	}

	public static void main(String[] args)
	{
		ConfigurationBuilder<BuiltConfiguration> builder
		 	= ConfigurationBuilderFactory.newConfigurationBuilder();
		
		AppenderComponentBuilder consoleAppender = builder.newAppender("stdout", "Console"); 
		
		LayoutComponentBuilder layoutBuilder = builder.newLayout("PatternLayout");
		layoutBuilder.addAttribute("pattern", "[%t] %-p %c: %x %m%n");
		consoleAppender.add(layoutBuilder);
		
		RootLoggerComponentBuilder rootLoggerBuilder = builder.newRootLogger(Level.TRACE);
		rootLoggerBuilder.add(builder.newAppenderRef("stdout"));
		builder.add(rootLoggerBuilder);
		
		
		AssertionSignatureChecker checker;
		try
		{
			checker = new AssertionSignatureChecker();
			DigSignatureUtil dsigEngine = new DigSignatureUtil();
			Document doc = checker.readDoc(null);
			AssertionDocument asXDoc = AssertionDocument.Factory.parse(doc);
			AssertionParser assertion = new AssertionParser(asXDoc);
			X509Certificate []certChain = assertion.getIssuerFromSignature();
			if (certChain == null || certChain.length == 0)
			{
				System.err.println("Can't read issuer certificate from the assertion.");
				return;
			}
			
			//BigInteger modulus = new BigInteger("CA47641C831BF6B89CE6E0980242E24DAA0DA66E3E91710368A751A008C3EFEEA707ACABC54F31ADB14394CD1B49A9A72EA63A16F6E8556B01A06BB89B9ADF5B50E506A981C2E406F72EB4F2BEE309556DBDDBAD807CF40E38E7C9286ECFD90F2CE52DD1C916E6C4D9E99EF58052CD9BAF75CD39F21D840B206E2C601585E857", 16);
			//BigInteger expotent = new BigInteger("65537");
			//PublicKey pubKey = new RSAPublicKeyImpl(modulus, expotent);
			PublicKey pubKey = certChain[0].getPublicKey(); 
			boolean res = dsigEngine.verifyEnvelopedSignature((Document) asXDoc.getDomNode(), 
					Collections.singletonList(doc.getDocumentElement()), 
					SamlTrustChecker.ASSERTION_ID_QNAME, pubKey);
			System.out.println("Signature is valid: " + res);
		} catch (Exception e)
		{
			e.printStackTrace();
		}
	}


	private Document readDoc(String file) throws Exception
	{
		if(file==null){
			Document inputDoc = documentBuilder.parse(System.in);
			return inputDoc;
		}
		else{
			FileInputStream fis = new FileInputStream(file);
			try{
				Document inputDoc = documentBuilder.parse(fis);
				return inputDoc;
			} finally {
				fis.close();
			}
		}
	}
}
