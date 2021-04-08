/*
 * Copyright (c) 2021 Bixbit - Krzysztof Benedyczak. All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.samly2.trust;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import java.security.PublicKey;
import java.util.Optional;
import java.util.function.Consumer;

import org.assertj.core.api.Assertions;
import org.assertj.core.util.Lists;
import org.junit.Test;

import eu.unicore.samly2.exceptions.SAMLValidationException;
import eu.unicore.samly2.messages.SAMLVerifiableElement;
import eu.unicore.security.dsig.DSigException;
import xmlbeans.org.oasis.saml2.assertion.NameIDType;

public class SignatureCheckerTest
{
	private PublicKey pk1 = mock(PublicKey.class);
	private PublicKey pk2 = mock(PublicKey.class);
	private NameIDType name = mock(NameIDType.class);
	
	@Test
	public void shouldAcceptSecondSigningKey()
	{
		SignatureChecker checker = new SignatureChecker(name -> Lists.list(pk1, pk2));
		
		Throwable error = Assertions.catchThrowable(() -> checker.verify(name, new FakeVerifiableElement(null, true, 
				pk -> 
				{
					if (pk != pk1) 
						throw new IllegalArgumentException("wrong");
				})));
		
		assertThat(error).isNull();
	}

	@Test
	public void shouldAcceptSingleSigningKey()
	{
		SignatureChecker checker = new SignatureChecker(name -> Lists.list(pk1));
		
		Throwable error = Assertions.catchThrowable(() -> checker.verify(name, new FakeVerifiableElement(null, true, 
				pk -> 
				{
					if (pk != pk1) 
						throw new IllegalArgumentException("wrong");
				})));
		
		assertThat(error).isNull();		
	}

	@Test
	public void shouldDenyOnNoMatchingKey()
	{
		SignatureChecker checker = new SignatureChecker(name -> Lists.list(pk1, pk2));
		
		Throwable error = Assertions.catchThrowable(() -> checker.verify(name, new FakeVerifiableElement(null, true, 
				pk -> 
				{
					throw new IllegalArgumentException("wrong");
				})));
		
		assertThat(error).isInstanceOf(SAMLValidationException.class);		
	}

	
	private static class FakeVerifiableElement implements SAMLVerifiableElement
	{
		private final PublicKey sigKey;
		private final boolean signed;
		private final Consumer<PublicKey> checker;

		FakeVerifiableElement(PublicKey sigKey, boolean signed, Consumer<PublicKey> checker)
		{
			this.sigKey = sigKey;
			this.signed = signed;
			this.checker = checker;
		}

		@Override
		public void verifySignature(PublicKey publicKey) throws DSigException
		{
			try
			{
				checker.accept(publicKey);
			} catch (Exception e)
			{
				throw new DSigException(e.toString());
			}
		}

		@Override
		public Optional<PublicKey> getSignatureKey()
		{
			return Optional.ofNullable(sigKey);
		}

		@Override
		public boolean isSigned()
		{
			return signed;
		}
	}
}
