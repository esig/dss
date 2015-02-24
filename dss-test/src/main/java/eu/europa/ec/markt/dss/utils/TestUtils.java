package eu.europa.ec.markt.dss.utils;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.Signature;

import eu.europa.ec.markt.dss.SignatureAlgorithm;
import eu.europa.ec.markt.dss.exception.DSSException;

public final class TestUtils {

	private TestUtils(){
	}

	public static byte[] sign(final SignatureAlgorithm signatureAlgorithm, final PrivateKey privateKey, final byte[] bytes) {
		try {
			final Signature signature = Signature.getInstance(signatureAlgorithm.getJCEId());
			signature.initSign(privateKey);
			signature.update(bytes);
			final byte[] signatureValue = signature.sign();
			return signatureValue;
		} catch (GeneralSecurityException e) {
			throw new DSSException(e);
		}
	}

}
