package eu.europa.esig.dss.pades;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.pdf.FixedSecureRandomProvider;

public class FixedSecureRandomProviderTest {

	private static Stream<Arguments> data() {
		Object[] arr = { DigestAlgorithm.MD2, DigestAlgorithm.MD5, DigestAlgorithm.SHA1, DigestAlgorithm.SHA224, DigestAlgorithm.SHA256,
				DigestAlgorithm.SHA384, DigestAlgorithm.SHA512, DigestAlgorithm.SHA3_224, DigestAlgorithm.SHA3_512 };
		return random(arr);
	}

	static Stream<Arguments> random(Object[] arr) {
		List<Arguments> args = new ArrayList<>();
		for (int i = 0; i < arr.length; i++) {
			args.add(Arguments.of(arr[i], getRandomLength()));
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
	public void signatureParametersTest(DigestAlgorithm digestAlgorithm, int byteArrayLength) throws IOException {
		FixedSecureRandomProvider fixedSecureRandomProvider = new FixedSecureRandomProvider();
		fixedSecureRandomProvider.setDigestAlgorithm(digestAlgorithm);
		fixedSecureRandomProvider.setBinaryLength(byteArrayLength);
		
		Date date = new Date();
		
		PAdESSignatureParameters signatureParameters = new PAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(date);
		SecureRandom secureRandom = fixedSecureRandomProvider.getSecureRandom(signatureParameters);
		
		byte[] byteArray = getEmptyBytes();
		secureRandom.nextBytes(byteArray);

		PAdESSignatureParameters otherSignatureParameters = new PAdESSignatureParameters();
		otherSignatureParameters.bLevel().setSigningDate(date);
		secureRandom = fixedSecureRandomProvider.getSecureRandom(otherSignatureParameters);
		
		byte[] sameByteArray = getEmptyBytes();
		secureRandom.nextBytes(sameByteArray);
		assertArrayEquals(byteArray, sameByteArray);
		
		otherSignatureParameters.setFilter("PDFFilter");
		secureRandom = fixedSecureRandomProvider.getSecureRandom(otherSignatureParameters);
		
		byte[] secondByteArray = getEmptyBytes();
		secureRandom.nextBytes(secondByteArray);
		
		assertFalse(Arrays.equals(byteArray, secondByteArray));
	}
	
	@Test
	public void propertiesTest() {
		FixedSecureRandomProvider fixedSecureRandomProvider = new FixedSecureRandomProvider();
		assertThrows(NullPointerException.class, () -> fixedSecureRandomProvider.setDigestAlgorithm(null));
		assertThrows(DSSException.class, () -> fixedSecureRandomProvider.setBinaryLength(-1));
		assertThrows(DSSException.class, () -> fixedSecureRandomProvider.setBinaryLength(0));
		assertThrows(DSSException.class, () -> fixedSecureRandomProvider.setBinaryLength(1));
		assertThrows(DSSException.class, () -> fixedSecureRandomProvider.setBinaryLength(15));
		fixedSecureRandomProvider.setBinaryLength(16);
		fixedSecureRandomProvider.setBinaryLength(1024);
		fixedSecureRandomProvider.setBinaryLength(50000);
	}
	
	private byte[] getEmptyBytes() {
		return new byte[16];
	}

}
