package eu.europa.esig.dss.cades.requirements;

import static org.junit.Assert.assertTrue;

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
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;

public class CAdESBaselineBTest extends AbstractRequirementChecks {

	@Override
	protected DSSDocument getSignedDocument() throws Exception {
		DSSDocument documentToSign = new InMemoryDocument("Hello world".getBytes());

		CertificateService certificateService = new CertificateService();
		MockPrivateKeyEntry privateKeyEntry = certificateService.generateCertificateChain(SignatureAlgorithm.RSA_SHA256);

		CAdESSignatureParameters signatureParameters = new CAdESSignatureParameters();
		signatureParameters.setSigningCertificate(privateKeyEntry.getCertificate());
		signatureParameters.setCertificateChain(privateKeyEntry.getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);

		CertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		CAdESService service = new CAdESService(certificateVerifier);

		ToBeSigned dataToSign = service.getDataToSign(documentToSign, signatureParameters);
		SignatureValue signature = TestUtils.sign(SignatureAlgorithm.RSA_SHA256, privateKeyEntry, dataToSign);
		return service.signDocument(documentToSign, signatureParameters, signature);
	}

	@Override
	public void checkSignatureTimeStampPresent() {
		// Not present in baseline B
	}

	@Override
	public void checkCertificateValue() {
		int counter = countUnsignedAttribute(PKCSObjectIdentifiers.id_aa_ets_certValues);
		assertTrue((counter == 0) || (counter == 1));
	}

	@Override
	public void checkCompleteCertificateReference() {
		int counter = countUnsignedAttribute(PKCSObjectIdentifiers.id_aa_ets_certificateRefs);
		assertTrue((counter == 0) || (counter == 1));
	}

	@Override
	public void checkRevocationValues() {
		int counter = countUnsignedAttribute(PKCSObjectIdentifiers.id_aa_ets_revocationValues);
		assertTrue((counter == 0) || (counter == 1));
	}

	@Override
	public void checkCompleteRevocationReferences() {
		int counter = countUnsignedAttribute(PKCSObjectIdentifiers.id_aa_ets_revocationRefs);
		assertTrue((counter == 0) || (counter == 1));
	}

	@Override
	public void checkCAdESCTimestamp() {
		int counter = countUnsignedAttribute(PKCSObjectIdentifiers.id_aa_ets_escTimeStamp);
		assertTrue(counter >= 0);
	}

	@Override
	public void checkTimestampedCertsCrlsReferences() {
		int counter = countUnsignedAttribute(PKCSObjectIdentifiers.id_aa_ets_certCRLTimestamp);
		assertTrue(counter >= 0);
	}

}
