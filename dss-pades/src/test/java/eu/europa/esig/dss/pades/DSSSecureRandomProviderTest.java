/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.pades;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.pdf.encryption.DSSSecureRandomProvider;
import eu.europa.esig.dss.pdf.encryption.SecureRandomProvider;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DSSSecureRandomProviderTest {

	private static Stream<Arguments> data() {
		Object[] arr = { DigestAlgorithm.MD2, DigestAlgorithm.MD5, DigestAlgorithm.SHA1, DigestAlgorithm.SHA224, DigestAlgorithm.SHA256,
				DigestAlgorithm.SHA384, DigestAlgorithm.SHA512, DigestAlgorithm.SHA3_224, DigestAlgorithm.SHA3_512 };
		return random(arr);
	}

	static Stream<Arguments> random(Object[] arr) {
		List<Arguments> args = new ArrayList<>();
		for (Object o : arr) {
			args.add(Arguments.of(o, getRandomLength()));
		}
		return args.stream();
	}
	
	private static int getRandomLength() {
		SecureRandom r = new SecureRandom();
		int low = 16;
		int high = 1024;
		return r.nextInt(high-low) + low;
	}

	@ParameterizedTest(name = "DigestAlgorithm {index} : {0} - {1}")
	@MethodSource("data")
	void signatureParametersTest(DigestAlgorithm digestAlgorithm, int byteArrayLength) throws IOException {
		Date date = new Date();
		
		PAdESSignatureParameters signatureParameters = new PAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(date);

		SecureRandomProvider secureRandomProvider = getFixedSecureRandomProvider(signatureParameters, digestAlgorithm, byteArrayLength);
		SecureRandom secureRandom = secureRandomProvider.getSecureRandom();
		
		byte[] byteArray = getEmptyBytes();
		secureRandom.nextBytes(byteArray);

		PAdESSignatureParameters otherSignatureParameters = new PAdESSignatureParameters();
		otherSignatureParameters.bLevel().setSigningDate(date);

		secureRandomProvider = getFixedSecureRandomProvider(otherSignatureParameters, digestAlgorithm, byteArrayLength);
		secureRandom = secureRandomProvider.getSecureRandom();
		
		byte[] sameByteArray = getEmptyBytes();
		secureRandom.nextBytes(sameByteArray);
		assertArrayEquals(byteArray, sameByteArray);
		
		otherSignatureParameters.setFilter("PDFFilter");

		secureRandomProvider = getFixedSecureRandomProvider(otherSignatureParameters, digestAlgorithm, byteArrayLength);
		secureRandom = secureRandomProvider.getSecureRandom();
		
		byte[] secondByteArray = getEmptyBytes();
		secureRandom.nextBytes(secondByteArray);
		
		assertFalse(Arrays.equals(byteArray, secondByteArray));
	}
	
	private DSSSecureRandomProvider getFixedSecureRandomProvider(
			PAdESCommonParameters parameters, DigestAlgorithm digestAlgorithm, int byteArrayLength) {
		DSSSecureRandomProvider fixedSecureRandomProvider = new DSSSecureRandomProvider(parameters);
		fixedSecureRandomProvider.setDigestAlgorithm(digestAlgorithm);
		fixedSecureRandomProvider.setBinaryLength(byteArrayLength);
		return fixedSecureRandomProvider;
	}
	
	@Test
	void propertiesTest() {
		PAdESSignatureParameters parameters = new PAdESSignatureParameters();
		DSSSecureRandomProvider fixedSecureRandomProvider = new DSSSecureRandomProvider(parameters);
		assertThrows(NullPointerException.class, () -> fixedSecureRandomProvider.setDigestAlgorithm(null));
		assertThrows(IllegalArgumentException.class, () -> fixedSecureRandomProvider.setBinaryLength(-1));
		assertThrows(IllegalArgumentException.class, () -> fixedSecureRandomProvider.setBinaryLength(0));
		assertThrows(IllegalArgumentException.class, () -> fixedSecureRandomProvider.setBinaryLength(1));
		assertThrows(IllegalArgumentException.class, () -> fixedSecureRandomProvider.setBinaryLength(15));
		fixedSecureRandomProvider.setBinaryLength(16);
		fixedSecureRandomProvider.setBinaryLength(1024);
		fixedSecureRandomProvider.setBinaryLength(50000);
	}
	
	private byte[] getEmptyBytes() {
		return new byte[16];
	}

	@Test
	void propertiesNullTest() {
		Exception exception = assertThrows(NullPointerException.class, () -> new DSSSecureRandomProvider((PAdESCommonParameters) null));
		assertEquals("Parameters must be defined! Unable to instantiate DSSSecureRandomProvider.", exception.getMessage());
		exception = assertThrows(NullPointerException.class, () -> new DSSSecureRandomProvider((SignatureImageParameters) null));
		assertEquals("Parameters must be defined! Unable to instantiate DSSSecureRandomProvider.", exception.getMessage());
	}

	@Test
	void signatureImageParametersTest() {
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.getTextParameters().setText("Hello World!");

		byte[] firstByteArray = getEmptyBytes();
		new DSSSecureRandomProvider(imageParameters).getSecureRandom().nextBytes(firstByteArray);
		byte[] secondByteArray = getEmptyBytes();
		new DSSSecureRandomProvider(imageParameters).getSecureRandom().nextBytes(secondByteArray);
		assertTrue(Arrays.equals(firstByteArray, secondByteArray));

		PAdESSignatureParameters signatureParameters = new PAdESSignatureParameters();
		signatureParameters.setImageParameters(imageParameters);

		byte[] firstSigParamsByteArray = getEmptyBytes();
		new DSSSecureRandomProvider(signatureParameters).getSecureRandom().nextBytes(firstSigParamsByteArray);
		byte[] secondSigParamsByteArray = getEmptyBytes();
		new DSSSecureRandomProvider(signatureParameters).getSecureRandom().nextBytes(secondSigParamsByteArray);
		assertTrue(Arrays.equals(firstSigParamsByteArray, secondSigParamsByteArray));

		imageParameters.getTextParameters().setText("Bye World!");
		byte[] thirdByteArray = getEmptyBytes();
		new DSSSecureRandomProvider(imageParameters).getSecureRandom().nextBytes(thirdByteArray);
		assertFalse(Arrays.equals(firstByteArray, thirdByteArray));

		byte[] thirdSigParamsByteArray = getEmptyBytes();
		new DSSSecureRandomProvider(signatureParameters).getSecureRandom().nextBytes(thirdSigParamsByteArray);
		assertFalse(Arrays.equals(firstSigParamsByteArray, thirdSigParamsByteArray));
	}

}
