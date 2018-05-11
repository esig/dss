package eu.europa.esig.dss.cades.requirements;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.OID;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignaturePackaging;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.signature.CAdESService;

public class CAdESBaselineTTest extends AbstractRequirementChecks {

	@Override
	protected DSSDocument getSignedDocument() throws Exception {
		DSSDocument documentToSign = new InMemoryDocument("Hello world".getBytes());

		CAdESSignatureParameters signatureParameters = new CAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_T);

		CAdESService service = new CAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());

		ToBeSigned dataToSign = service.getDataToSign(documentToSign, signatureParameters);
		SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		return service.signDocument(documentToSign, signatureParameters, signatureValue);
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

	@Override
	public void checkArchiveTimeStampV3() {
		int counter = countUnsignedAttribute(OID.id_aa_ets_archiveTimestampV3);
		assertEquals(0, counter);
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
