package eu.europa.esig.dss.cades.validation;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import org.bouncycastle.tsp.TimeStampToken;
import org.junit.Test;

import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.SignatureAlgorithm;
import eu.europa.esig.dss.test.gen.CertificateService;
import eu.europa.esig.dss.test.mock.MockTSPSource;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.TimestampToken;

public class CMSTimestampValidatorTest {

	@Test
	public void testValidator() throws Exception {
		CertificateService certificateService = new CertificateService();
		MockTSPSource mockTSPSource = new MockTSPSource(certificateService.generateTspCertificate(SignatureAlgorithm.RSA_SHA256));

		byte[] data = new byte[] { 1, 2, 3 };
		TimeStampToken timeStampResponse = mockTSPSource.getTimeStampResponse(DigestAlgorithm.SHA256, DSSUtils.digest(DigestAlgorithm.SHA256, data));

		CMSTimestampValidator validator = new CMSTimestampValidator(new InMemoryDocument(timeStampResponse.getEncoded()));
		validator.setTimestampedData(new InMemoryDocument(data));
		validator.setCertificateVerifier(new CommonCertificateVerifier());

		assertTrue(Utils.isCollectionEmpty(validator.getSignatures()));

		TimestampToken timestamp = validator.getTimestamp();
		assertNotNull(timestamp);
		assertTrue(timestamp.isMessageImprintDataFound());
		assertTrue(timestamp.isMessageImprintDataIntact());
	}

}
