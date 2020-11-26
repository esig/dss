package eu.europa.esig.dss.jades.validation;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import javax.security.auth.x500.X500Principal;

import org.jose4j.json.internal.json_simple.JSONObject;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLRef;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPRef;
import eu.europa.esig.dss.utils.Utils;

public class JAdESRevocationRefExtractionUtilsTest {

	private static final Logger LOG = LoggerFactory.getLogger(JAdESRevocationRefExtractionUtilsTest.class);

	@Test
	@SuppressWarnings("unchecked")
	public void getOCSPRef() {

		JSONObject ocspRefJson = new JSONObject();

		JSONObject ocspIdJson = new JSONObject();
		
		JSONObject responderIdJson = new JSONObject();
		responderIdJson.put("byName", Utils.toBase64(new X500Principal("C=BE,O=MyOrg,CN=Test").getEncoded()));
		ocspIdJson.put("responderId", responderIdJson);

		ocspIdJson.put("producedAt", "2020-07-10T08:40:30Z");
		ocspRefJson.put("ocspId", ocspIdJson);

		ocspRefJson.put("digAlg", DigestAlgorithm.SHA256.getJAdESId());
		ocspRefJson.put("digVal", Utils.toBase64(DSSUtils.digest(DigestAlgorithm.SHA256, "Hello".getBytes())));

		LOG.info(ocspRefJson.toJSONString());

		OCSPRef ocspRef = JAdESRevocationRefExtractionUtils.createOCSPRef(ocspRefJson);
		assertNotNull(ocspRef);
		assertNotNull(ocspRef.getDigest());
		assertNotNull(ocspRef.getProducedAt());
		assertNotNull(ocspRef.getResponderId());
		assertNotNull(ocspRef.getResponderId().getX500Principal());
		assertNull(ocspRef.getResponderId().getSki());
	}

	@Test
	@SuppressWarnings("unchecked")
	public void getCRLRef() {

		JSONObject crlRefJson = new JSONObject();

		crlRefJson.put("digAlg", DigestAlgorithm.SHA256.getJAdESId());
		crlRefJson.put("digVal", Utils.toBase64(DSSUtils.digest(DigestAlgorithm.SHA256, "Hello".getBytes())));

		JSONObject crlId = new JSONObject();
		crlId.put("issuer", Utils.toBase64(new X500Principal("C=BE,O=MyOrg,CN=Test").getEncoded()));
		crlId.put("issueTime", "2020-07-10T08:40:30Z");
		crlId.put("number", "2");

		crlRefJson.put("crlId", crlId);

		LOG.info(crlRefJson.toJSONString());

		CRLRef crlRef = JAdESRevocationRefExtractionUtils.createCRLRef(crlRefJson);
		assertNotNull(crlRef);
		assertNotNull(crlRef.getDigest());
		assertNotNull(crlRef.getCrlIssuedTime());
		assertNotNull(crlRef.getCrlIssuer());
		assertNotNull(crlRef.getCrlNumber());

	}

}
