/*
 * Copyright (c) 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on 2008-09-26
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.security;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;

import javax.security.auth.x500.X500Principal;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;

import eu.unicore.crlcheck.CRLCheckResult;
import eu.unicore.crlcheck.CRLManager;
import eu.unicore.crlcheck.CRLManagerProperties;

/**
 * Verifies if the certificate is not expired or revoked (if CRL check is configured)
 * Also, additional certificate handling utils are provided. 
 * <p>
 * This class is used internally by other APIs. Every certificate which is used
 * at any <b>validation</b> (e.g. check if ETD assertion is valid) is checked. 
 * By default certificates used in any <b>generation</b> (e.g. creation of Consignor token)
 * is not checked. You can change this behavior by setting
 * VERIFY_GENERATION_KEY property to "true".
 * 
 * @author golbi
 */
public class CertificateUtils
{
	private static final Logger log = Logger.getLogger(CertificateUtils.class);
	
	public static final String VERIFY_GENERATION_KEY = "eu.unicore.securty.VerifyExpiredCertUponCreation";
	public static final String CRLMGR_PROPS_FILE     = "crlmanager.properties.file";

	private static CRLManager crlManager = null;

	static {
		String crlManagerPropertiesFile=System.getProperty(CRLMGR_PROPS_FILE);
		if(crlManagerPropertiesFile!=null){
			CRLManagerProperties crlMgrProps = new CRLManagerProperties();
			FileInputStream fis=null;
			try
			{
				fis=new FileInputStream(crlManagerPropertiesFile);
				crlMgrProps.load(fis);
			}
			catch (Exception e)
			{
				System.err.println("Error initialising CRL checker.");
				e.printStackTrace();
			}
			finally{
				if(fis!=null)try{fis.close();}catch(IOException ignored){}
			}
			crlManager=CRLManager.getInstance(crlMgrProps);
		}

	}

	public static void verifyCertificate(X509Certificate cert, boolean doCRLCheck, boolean isGenerateMode) throws CertificateExpiredException, CertificateNotYetValidException
	{
		String verify = System.getProperty(CertificateUtils.VERIFY_GENERATION_KEY);
		if (!isGenerateMode || (verify != null && verify.equals("true"))) cert.checkValidity();

		if (doCRLCheck && crlManager!=null)
		{
			CRLCheckResult cr = crlManager.checkCertificate(cert);
			if (!cr.isValid())
			{
				// TODO Is there a better exception for this?
				throw new CertificateExpiredException("CRL check failed: "+cr.getReason());
			}
		}
	}

	public static void verifyCertificate(X509Certificate[] certs, boolean doCRLCheck, boolean isGenerateMode) throws CertificateExpiredException, CertificateNotYetValidException
	{
		for (X509Certificate cert : certs)
			verifyCertificate(cert, doCRLCheck, isGenerateMode);
	}

	public static String safePrintSubject(X509Certificate cert)
	{
		if (cert == null) return "EMPTY certificate";
		if (cert.getSubjectX500Principal() == null) return "certificate without a subject";
		return cert.getSubjectX500Principal().getName();
	}

	public static String safePrintSubject(X509Certificate[] cert)
	{
		if (cert == null || cert.length == 0) return "EMPTY certificate";
		return safePrintSubject(cert[0]);
	}
	
	/**
	 * Uppers the case of the arg, then lowers it, using non-locale specific 
	 * algorithm.
	 * @param src
	 * @return
	 */
	private static String upLowCase(String src) 
	{
		char[] chars = src.toCharArray();
		StringBuilder ret = new StringBuilder(chars.length);
		for (char c: chars) 
			ret.append(Character.toLowerCase(Character.toUpperCase(c)));
		return ret.toString();
	}
	
	/**
	 * Checks if two given DNs are equivalent, using JDK canonical {@link X500Principal} representation.
	 * This method is less strict then the original: it compares DC and EMAIL components in case 
	 * insensitive way. Input arguments with values encoded in hex are also correctly handled. What is more
	 * it supports DNs with attribute names normally not recognized by X500Principial.
	 * @param dn1 in RFC2253 encoding
	 * @param dn2 in RFC2253 encoding
	 * @return true iff are equivalent
	 */
	public static boolean dnEqual(String dn1, String dn2)
	{
		//first part: ensures that popular attribute names unsupported by JDK are encoded with OIDs
		// and converts all DC and EMAIL attributes to lower case.
		String rfcA = preNormalize(dn1);
		String rfcB = preNormalize(dn2);
		
		//Finally compare using CANONICAL forms.
		return new X500Principal(rfcA).equals(new X500Principal(rfcB));
	}
	
	/**
	 * Returns a form of the original DN which will be properly parsed by JDK {@link X500Principal} class by
	 * replacing attribute names unknown by the {@link X500Principal} with OIDs.
	 * What is more all DC and EMAIL values are converted to lower case.
	 * @param dn in RFC 2253 form.
	 * @return dn in RFC 2253 form, reformatted.
	 */
	public static String preNormalize(String dn)
	{
		RDN[] rdns;
		try 
		{
			rdns = IETFUtils.rDNsFromString(dn, JavaAndBCStyle.INSTANCE);
		} catch (IllegalArgumentException e)
		{
			log.warn("BC can't parse the DN " + dn + ". Won't normalize this DN. " +
					"Problem: " + e.toString());
			return dn;
		}
		X500NameBuilder builder = new X500NameBuilder(JavaAndBCStyle.INSTANCE);
		
		for (RDN rdn: rdns)
		{
			if (rdn.isMultiValued())
			{
				AttributeTypeAndValue avas[] = rdn.getTypesAndValues();
				for (int j=0; j<avas.length; j++)
					avas[j] = normalizeAVA(avas[j]);
				builder.addMultiValuedRDN(avas);
			} else
			{
				AttributeTypeAndValue ava = rdn.getFirst();
				builder.addRDN(normalizeAVA(ava));
			}
		}
		return JavaAndBCStyle.INSTANCE.toString(builder.build());
	}
	
	private static AttributeTypeAndValue normalizeAVA(AttributeTypeAndValue orig)
	{
		if (orig.getType().equals(BCStyle.DC) || 
				orig.getType().equals(BCStyle.EmailAddress))
		{
			ASN1Encodable value = orig.getValue();
			if (value instanceof ASN1String)
			{
				if (!(value instanceof DERIA5String)) 
					log.warn("SHOULDN'T HAPPEN: AVA " + 
							orig.getType().getId() + " with value " 
							+ value.toString() + 
							" is not of the expected type IA5String but of other string type: " +
							orig.getType().toString());
				ASN1String ia5Str = (ASN1String) value;
				String newValue = upLowCase(ia5Str.getString());
				return new AttributeTypeAndValue(orig.getType(), 
					new DERIA5String(newValue));
			} else
			{
				log.warn("SHOULDN'T HAPPEN: AVA " + 
						orig.getType().getId() + 
						" is not of the expected type IA5String but of: " +
						orig.getType().toString());
				return orig;
			}
		} else
			return orig;
		
	}
	
	/**
	 * Checks if two given DNs are equivalent. This method ensures NOT to use any detailed
	 * information from the binary representation of the first argument.
	 * @param p1 possibly binary represenation of a name
	 * @param dn2
	 * @return true iff are equivalent
	 */
	public static boolean dnEqual(X500Principal p1, String dn2)
	{
		//do it carefully: first loose any ASN.1 info, then compare text versions
		String dn1Str = p1.getName();
		return dnEqual(dn1Str, dn2);
	}
	
	
	/**
	 * Checks if two given {@link X500Principal} are equivalent. 
	 * This method ensures NOT to use any detailed information from the binary 
	 * representation of the arguments, so it can return true even if parameter's equals() 
	 * returns false. It has the same semantics as other dnEqual methods in this class.
	 * @param p1 
	 * @param p2
	 * @return true iff are equivalent
	 */
	public static boolean principalsSoftEqual(X500Principal p1, X500Principal p2) 
	{
		return dnEqual(p1.getName(), p2.getName());
	}
}
