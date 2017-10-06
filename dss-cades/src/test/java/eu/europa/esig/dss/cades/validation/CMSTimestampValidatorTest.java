package eu.europa.esig.dss.cades.validation;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import org.bouncycastle.tsp.TimeStampToken;
import org.junit.Test;

import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.signature.PKIFactoryAccess;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.TimestampToken;
import eu.europa.esig.dss.x509.tsp.TSPSource;

public class CMSTimestampValidatorTest extends PKIFactoryAccess {

	@Test
	public void testValidator() throws Exception {

		TSPSource tspSource = getGoodTsa();

		byte[] data = new byte[] { 1, 2, 3 };
		TimeStampToken timeStampResponse = tspSource.getTimeStampResponse(DigestAlgorithm.SHA256, DSSUtils.digest(DigestAlgorithm.SHA256, data));

		CMSTimestampValidator validator = new CMSTimestampValidator(new InMemoryDocument(timeStampResponse.getEncoded()));
		validator.setTimestampedData(new InMemoryDocument(data));
		validator.setCertificateVerifier(getCompleteCertificateVerifier());

		assertTrue(Utils.isCollectionEmpty(validator.getSignatures()));

		TimestampToken timestamp = validator.getTimestamp();
		assertNotNull(timestamp);
		assertTrue(timestamp.isMessageImprintDataFound());
		assertTrue(timestamp.isMessageImprintDataIntact());
	}

	@Override
	protected String getSigningAlias() {
		// not for signing
		return null;
	}

}
