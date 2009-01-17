/*
 * Copyright (c) 2007, 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on May 30, 2007
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package pl.edu.icm.samly2.dsig;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.logging.Logger;

/**
 * Auxiliary static methods.
 * @author K. Benedyczak
 */
public class Utils
{
	private static final Logger log = Logger.getLogger(Utils.class.getName());

	public static X509Certificate deserializeCertificate(byte []encodedCert)
	{
		CertificateFactory cf;
		try
		{
			cf = CertificateFactory.getInstance("X.509");
		} catch (CertificateException e1)
		{
			log.warning("Can't initialize certificate factory for X509 certificates");
			return null;
		}
		ByteArrayInputStream bais = new ByteArrayInputStream(encodedCert);
		try
		{
			X509Certificate cert = (X509Certificate) cf.generateCertificate(bais);
			return cert;
		} catch (CertificateException e)
		{
			log.warning("Error while deserializing certificate from key info: " + e);
			return null;
		} catch (ClassCastException e)
		{
			log.warning("Unknown type of certificate in key info");
			return null;
		}
	}
	
	public static X509Certificate[] deserializeCertificateChain(byte [][]encodedCerts)
	{
		X509Certificate []retval = new X509Certificate[encodedCerts.length];
		for (int i=0; i<encodedCerts.length; i++)
			retval[i] = deserializeCertificate(encodedCerts[i]);
		return retval;
	}

}
