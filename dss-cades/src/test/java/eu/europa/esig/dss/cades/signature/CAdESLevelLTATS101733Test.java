package eu.europa.esig.dss.cades.signature;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.util.Collection;
import java.util.Date;
import java.util.List;

import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.tsp.TimeStampToken;
import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.OID;
import eu.europa.esig.dss.test.signature.PKIFactoryAccess;
import eu.europa.esig.dss.validation.DefaultDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

public class CAdESLevelLTATS101733Test extends PKIFactoryAccess {

	@Test
	public void test() throws Exception {
		DSSDocument documentToSign = new InMemoryDocument("Hello World !".getBytes(), "test.text");

		CAdESSignatureParameters signatureParameters = new CAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LTA);
		signatureParameters.setEn319122(false);

		CAdESService service = new CAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());

		ToBeSigned dataToSign = service.getDataToSign(documentToSign, signatureParameters);
		SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument signedDocument = service.signDocument(documentToSign, signatureParameters, signatureValue);
		
		DefaultDocumentValidator validator = DefaultDocumentValidator.fromDocument(signedDocument);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());

		Reports reports = validator.validateDocument();

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		
		List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
		assertEquals(2, timestampList.size());
		int archiveTimestampCounter = 0;
		for (TimestampWrapper timestamp : timestampList) {
			assertTrue(timestamp.isMessageImprintDataFound());
			assertTrue(timestamp.isMessageImprintDataIntact());
			if (timestamp.getType().isArchivalTimestamp()) {
				++archiveTimestampCounter;
			}
		}
		assertEquals(1, archiveTimestampCounter);
		
		try (InputStream is = signedDocument.openStream()) {
			CMSSignedData cmsSignedData = new CMSSignedData(is);
			Collection<SignerInformation> signers = cmsSignedData.getSignerInfos().getSigners();
			assertEquals(1, signers.size());
			for (SignerInformation signerInformation : signers) {
				AttributeTable unsignedAttributes = signerInformation.getUnsignedAttributes();
				Attribute[] attributes = DSSASN1Utils.getAsn1Attributes(unsignedAttributes, OID.id_aa_ets_archiveTimestampV3);
				assertEquals(1, attributes.length);
				Attribute archiveTimestamp = attributes[0];
				
				TimeStampToken timeStampToken = DSSASN1Utils.getTimeStampToken(archiveTimestamp);
				AttributeTable unsignedAttributes2 = timeStampToken.getUnsignedAttributes();
				Attribute[] asn1Attributes = DSSASN1Utils.getAsn1Attributes(unsignedAttributes2, OID.id_aa_ATSHashIndex);
				assertEquals(1, asn1Attributes.length);
			}
		}
		
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
