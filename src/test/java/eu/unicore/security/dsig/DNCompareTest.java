/*
 * Copyright (c) 2010 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on 2011-08-05
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */
package eu.unicore.security.dsig;

import javax.security.auth.x500.X500Principal;

import eu.unicore.security.CertificateUtils;
import junit.framework.TestCase;

public class DNCompareTest  extends TestCase
{
	/**
	 *  
	 *  CN      commonName (2.5.4.3)
	 *  L       localityName (2.5.4.7)
	 *  ST      stateOrProvinceName (2.5.4.8)
	 *  O       organizationName (2.5.4.10)
	 *  OU      organizationalUnitName (2.5.4.11)
	 *  C       countryName (2.5.4.6)
	 *  STREET  streetAddress (2.5.4.9)
	 *  DC      domainComponent (0.9.2342.19200300.100.1.25)
	 *  UID     userId (0.9.2342.19200300.100.1.1)
	 */
	public void testDNs()
	{
		String dnA[] = {
				"CN=James \\\"Jim\\\" Smith\\, III,DC=net,L=Before\0dAfter,1.3.6.1.4.1.1466.0=#04024869,ST=Lu\\C4\\8Di\\C4\\87,O=org,OU=OtherUnit,C=Country+STREET=Multi valued Avenue+0.9.2342.19200300.100.1.1=multiValuedUid,EMAIL=email@is.also.recognized",
				"CN=James \\\"Jim\\\" Smith\\, III,DC=NET,L=Before\0dAfter,1.3.6.1.4.1.1466.0=#04024869,ST=Lu\\C4\\8Di\\C4\\87,O=org,OU=OtherUnit,C=Country+STREET=Multi valued Avenue+0.9.2342.19200300.100.1.1=multiValuedUid,EMAIL=email@is.ALSO.recognized",
				"CN=James \\\"Jim\\\" Smith\\, III, DC=net,L=Before\0dAfter,1.3.6.1.4.1.1466.0=#04024869,ST=Lu\\C4\\8Di\\C4\\87,O=org,OU=OtherUnit,C=Country+STREET=Multi valued Avenue+0.9.2342.19200300.100.1.1=multivaluedUid,EMAIL=email@is.also.recognized",
		};
		
		checkAll(true, dnA);
		
		String src = "CN=Ala ma kota, DC=nEt,EMAIL=golBi@localhost+DC=FFFF+C=PL,DC=kkL,EMAILADDRESS=ss@asddsfdsDDDD";
		String normalized = CertificateUtils.preNormalize(src);
		X500Principal x500 = new X500Principal(normalized);
		String dnB[] = {
				src,
				normalized,
				x500.getName(),
				x500.getName(X500Principal.CANONICAL),
				new X500Principal(src).getName(),
				new X500Principal(src).getName(X500Principal.CANONICAL)
		};
		
		checkAll(true, dnB);
		
		String dn1 = "EMAIL=e@at";
		String dn2 = "EMAIL=E@At";
		dn1 = new X500Principal(dn1).getName(X500Principal.CANONICAL);
		dn2 = new X500Principal(dn2).getName(X500Principal.CANONICAL);
		
		assertTrue(CertificateUtils.dnEqual(dn1, dn2));
	}
	
	private void checkAll(boolean mode, String []dn)
	{
		for (int i=0; i<dn.length; i++)
			for (int j=0; j<dn.length; j++)
			{
				boolean res = CertificateUtils.dnEqual(dn[i], dn[j]);
				
				if (mode && !res)
				{
					String msg = "DN " + i + " and " + j + " reported to be different.";
					System.err.println(msg);
					fail(msg);
				}
				if (!mode && res)
				{
					String msg = "DN " + i + " and " + j + " reported to be equivalent.";
					System.err.println(msg);
					fail(msg);
				}
			}
	}
}
