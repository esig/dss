package eu.europa.esig.dss.token;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore.PasswordProtection;
import java.security.Security;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.List;

import javax.crypto.Cipher;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSSecurityProvider;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.Digest;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.EncryptionAlgorithm;
import eu.europa.esig.dss.MaskGenerationFunction;
import eu.europa.esig.dss.SignatureAlgorithm;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;

@RunWith(Parameterized.class)
public class SignDigestRSASSAPSSTest {

	static {
		Security.addProvider(DSSSecurityProvider.getSecurityProvider());
	}

	private static final Logger LOG = LoggerFactory.getLogger(SignDigestRSASSAPSSTest.class);

	private final DigestAlgorithm digestAlgo;

	@Parameters(name = "DigestAlgorithm {index} : {0}")
	public static Collection<DigestAlgorithm> data() {
		Collection<DigestAlgorithm> rsaCombinations = new ArrayList<DigestAlgorithm>();
		for (DigestAlgorithm digestAlgorithm : DigestAlgorithm.values()) {
			if (SignatureAlgorithm.getAlgorithm(EncryptionAlgorithm.RSA, digestAlgorithm, MaskGenerationFunction.MGF1) != null) {
				rsaCombinations.add(digestAlgorithm);
			}
		}
		return rsaCombinations;
	}

	public SignDigestRSASSAPSSTest(DigestAlgorithm digestAlgo) {
		this.digestAlgo = digestAlgo;
	}

	@Test
	public void testPkcs12PSS() throws IOException {
		try (Pkcs12SignatureToken signatureToken = new Pkcs12SignatureToken("src/test/resources/user_a_rsa.p12",
				new PasswordProtection("password".toCharArray()))) {

			List<DSSPrivateKeyEntry> keys = signatureToken.getKeys();
			KSPrivateKeyEntry entry = (KSPrivateKeyEntry) keys.get(0);

			ToBeSigned toBeSigned = new ToBeSigned("Hello world".getBytes("UTF-8"));

			SignatureValue signValue = signatureToken.sign(toBeSigned, digestAlgo, MaskGenerationFunction.MGF1, entry);
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

			try {
				Cipher cipher = Cipher.getInstance(entry.getEncryptionAlgorithm().getName(),
						DSSSecurityProvider.getSecurityProviderName());
				cipher.init(Cipher.DECRYPT_MODE, entry.getCertificate().getPublicKey());
				byte[] decrypted = cipher.doFinal(signValue.getValue());
				LOG.info("Decrypted : {}", Base64.getEncoder().encodeToString(decrypted));
			} catch (GeneralSecurityException e) {
				Assert.fail(e.getMessage());
			}

			final byte[] digestBinaries = DSSUtils.digest(digestAlgo, toBeSigned.getBytes());
			Digest digest = new Digest(digestAlgo, digestBinaries);

			SignatureValue signDigestValue = signatureToken.signDigest(digest, MaskGenerationFunction.MGF1, entry);
			assertNotNull(signDigestValue.getAlgorithm());
			assertEquals(signValue.getAlgorithm(), signDigestValue.getAlgorithm());
			LOG.info("Sig value : {}", Base64.getEncoder().encodeToString(signDigestValue.getValue()));

			try {
				Signature sig = Signature.getInstance(signDigestValue.getAlgorithm().getJCEId());
				sig.initVerify(entry.getCertificate().getPublicKey());
				sig.update(toBeSigned.getBytes());
				assertTrue(sig.verify(signDigestValue.getValue()));
			} catch (GeneralSecurityException e) {
				Assert.fail(e.getMessage());
			}

			try {
				Cipher cipher = Cipher.getInstance(entry.getEncryptionAlgorithm().getName(),
						DSSSecurityProvider.getSecurityProviderName());
				cipher.init(Cipher.DECRYPT_MODE, entry.getCertificate().getPublicKey());
				byte[] decrypted = cipher.doFinal(signDigestValue.getValue());
				LOG.info("Decrypted : {}", Base64.getEncoder().encodeToString(decrypted));
			} catch (GeneralSecurityException e) {
				Assert.fail(e.getMessage());
			}

			// should not be equals
			assertNotEquals(Base64.getEncoder().encodeToString(signValue.getValue()), Base64.getEncoder().encodeToString(signDigestValue.getValue()));
		}
	}

}
