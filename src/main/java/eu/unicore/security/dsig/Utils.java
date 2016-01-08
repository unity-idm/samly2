/*
 * Copyright (c) 2007, 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on May 30, 2007
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.security.dsig;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.List;

import org.apache.log4j.Logger;

import eu.emi.security.authn.x509.impl.CertificateUtils;
import eu.emi.security.authn.x509.impl.CertificateUtils.Encoding;

/**
 * Auxiliary static methods.
 * @author K. Benedyczak
 */
public class Utils
{
	private static final Logger log = Logger.getLogger("unicore.security." + 
		Utils.class.getSimpleName());

	private static X509Certificate deserializeCertificate(byte []encodedCert)
	{
		ByteArrayInputStream bais = new ByteArrayInputStream(encodedCert);
		try
		{
			return CertificateUtils.loadCertificate(bais, Encoding.DER);
		} catch (IOException e)
		{
			log.warn("Error while deserializing certificate from key info: " + e);
			return null;
		}
	}
	
	public static X509Certificate[] deserializeCertificateChain(List<byte[]> encodedCerts)
	{
		X509Certificate []retval = new X509Certificate[encodedCerts.size()];
		for (int i=0; i<encodedCerts.size(); i++)
			retval[i] = deserializeCertificate(encodedCerts.get(i));
		return retval;
	}
}
