package eu.europa.esig.dss.cades.requirements;

import static org.junit.Assert.assertFalse;

import java.util.Date;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.SignatureAlgorithm;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.signature.SignaturePackaging;
import eu.europa.esig.dss.test.TestUtils;
import eu.europa.esig.dss.test.gen.CertificateService;
import eu.europa.esig.dss.test.mock.MockPrivateKeyEntry;
import eu.europa.esig.dss.test.mock.MockTSPSource;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;

public class CAdESBaselineLTTest extends AbstractRequirementChecks {

	@Override
	protected DSSDocument getSignedDocument() throws Exception {
		DSSDocument documentToSign = new InMemoryDocument("Hello world".getBytes());

		CertificateService certificateService = new CertificateService();
		MockPrivateKeyEntry privateKeyEntry = certificateService.generateCertificateChain(SignatureAlgorithm.RSA_SHA256);

		CAdESSignatureParameters signatureParameters = new CAdESSignatureParameters();
		signatureParameters.setSigningCertificate(privateKeyEntry.getCertificate());
		signatureParameters.setCertificateChain(privateKeyEntry.getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_T);

		CertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		CAdESService service = new CAdESService(certificateVerifier);
		service.setTspSource(new MockTSPSource(certificateService.generateTspCertificate(SignatureAlgorithm.RSA_SHA1), new Date()));

		ToBeSigned dataToSign = service.getDataToSign(documentToSign, signatureParameters);
		SignatureValue signature = TestUtils.sign(SignatureAlgorithm.RSA_SHA256, privateKeyEntry, dataToSign);
		return service.signDocument(documentToSign, signatureParameters, signature);
	}

	@Override
	public void checkCertificateValue() {
		assertFalse(isUnsignedAttributeFound(PKCSObjectIdentifiers.id_aa_ets_certValues));
	}

	@Override
	public void checkCompleteCertificateReference() {
		assertFalse(isUnsignedAttributeFound(PKCSObjectIdentifiers.id_aa_ets_certificateRefs));
	}

	@Override
	public void checkRevocationValues() {
		assertFalse(isUnsignedAttributeFound(PKCSObjectIdentifiers.id_aa_ets_revocationValues));
	}

	@Override
	public void checkCompleteRevocationReferences() {
		assertFalse(isUnsignedAttributeFound(PKCSObjectIdentifiers.id_aa_ets_revocationRefs));
	}

	@Override
	public void checkCAdESCTimestamp() {
		assertFalse(isUnsignedAttributeFound(PKCSObjectIdentifiers.id_aa_ets_escTimeStamp));
	}

	@Override
	public void checkTimestampedCertsCrlsReferences() {
		assertFalse(isUnsignedAttributeFound(PKCSObjectIdentifiers.id_aa_ets_certCRLTimestamp));
	}

}
