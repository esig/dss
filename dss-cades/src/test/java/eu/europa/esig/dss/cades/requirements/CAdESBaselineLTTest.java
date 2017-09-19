package eu.europa.esig.dss.cades.requirements;

import static org.junit.Assert.assertFalse;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignaturePackaging;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.signature.CAdESService;

public class CAdESBaselineLTTest extends AbstractRequirementChecks {

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

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
