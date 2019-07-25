package eu.europa.esig.dss.token;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore.PasswordProtection;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.List;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.Digest;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;

@RunWith(Parameterized.class)
public class SignDigestDSATest {

	private static final Logger LOG = LoggerFactory.getLogger(SignDigestDSATest.class);

	private final DigestAlgorithm digestAlgo;

	@Parameters(name = "DigestAlgorithm {index} : {0}")
	public static Collection<DigestAlgorithm> data() {
		Collection<DigestAlgorithm> ecdsaCombinations = new ArrayList<DigestAlgorithm>();
		for (DigestAlgorithm digestAlgorithm : DigestAlgorithm.values()) {
			if (isSupportedByJDK(digestAlgorithm) && SignatureAlgorithm.getAlgorithm(EncryptionAlgorithm.DSA, digestAlgorithm) != null) {
				ecdsaCombinations.add(digestAlgorithm);
			}
		}
		return ecdsaCombinations;
	}

	/**
	 * Data for RawDSA must be exactly 20 bytes long
	 * sun.security.provider.DSA.generateS(DSA.java:306)
	 */
	private static boolean isSupportedByJDK(DigestAlgorithm digestAlgorithm) {
		return digestAlgorithm.getSaltLength() <= 20;
	}

	public SignDigestDSATest(DigestAlgorithm digestAlgo) {
		this.digestAlgo = digestAlgo;
	}

	@Test
	public void testPkcs12() throws IOException {
		try (Pkcs12SignatureToken signatureToken = new Pkcs12SignatureToken("src/test/resources/good-dsa-user.p12",
				new PasswordProtection("ks-password".toCharArray()))) {

			List<DSSPrivateKeyEntry> keys = signatureToken.getKeys();
			KSPrivateKeyEntry entry = (KSPrivateKeyEntry) keys.get(0);

			ToBeSigned toBeSigned = new ToBeSigned("Hello world".getBytes("UTF-8"));

			SignatureValue signValue = signatureToken.sign(toBeSigned, digestAlgo, entry);
			assertNotNull(signValue.getAlgorithm());
			LOG.info("Sig value : {}", Base64.getEncoder().encodeToString(signValue.getValue()));
			try {
				Signature sig = Signature.getInstance(signValue.getAlgorithm().getJCEId());
				sig.initVerify(entry.getCertificate().getPublicKey());
				sig.update(toBeSigned.getBytes());
				assertTrue(sig.verify(signValue.getValue()));
			} catch (GeneralSecurityException e) {
				Assert.fail(e.getMessage());
			}

			final byte[] digestBinaries = DSSUtils.digest(digestAlgo, toBeSigned.getBytes());
			Digest digest = new Digest(digestAlgo, digestBinaries);

			SignatureValue signDigestValue = signatureToken.signDigest(digest, entry);
			assertNotNull(signDigestValue.getAlgorithm());
			LOG.info("Sig value : {}", Base64.getEncoder().encodeToString(signDigestValue.getValue()));

			try {
				Signature sig = Signature.getInstance(signDigestValue.getAlgorithm().getJCEId());
				sig.initVerify(entry.getCertificate().getPublicKey());
				sig.update(toBeSigned.getBytes());
				assertTrue(sig.verify(signDigestValue.getValue()));
			} catch (GeneralSecurityException e) {
				Assert.fail(e.getMessage());
			}

			// Sig values are not equals like with RSA. (random number is generated on
			// signature creation)
		}
	}
}
