package eu.europa.esig.dss.xades.validation.xsw;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.util.List;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.xades.validation.AbstractXAdESTestValidation;
import eu.europa.esig.validationreport.jaxb.SignersDocumentType;

public class XAdESEnvelopingFakeObjectTest extends AbstractXAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument(new File("src/test/resources/validation/xsw/XSW-enveloping-fake-object.xml"));
	}
	
	@Override
	protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
		SignedDocumentValidator validator = super.getValidator(signedDocument);
		
		CommonTrustedCertificateSource trustedListsCertificateSource = new CommonTrustedCertificateSource();
		
		CertificateToken rootToken = DSSUtils.loadCertificateFromBase64EncodedString(
				"MIID1DCCArygAwIBAgIBCjANBgkqhkiG9w0BAQsFADBNMRAwDgYDVQQDDAdnb29kLWNhMRkwFwYDVQQKDBBOb3dpbmEgU29sdXRpb25zMREwDwYDVQQLDAhQS0ktVEVTVDELMAkGA1UEBhMCTFUwHhcNMTcwOTI5MDg1NzMyWhcNMTkwNzI5MDg1NzMyWjBPMRIwEAYDVQQDDAlnb29kLXVzZXIxGTAXBgNVBAoMEE5vd2luYSBTb2x1dGlvbnMxETAPBgNVBAsMCFBLSS1URVNUMQswCQYDVQQGEwJMVTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJiJTCR/uqNZPWXpToBIOrH1ggpmmZ4Lq4aSkxPhkHTNacI59Va3WyCnrIRN3EgJraLJ+dp7CD/5wbh9Utu7UHG5vs2ZTifPIdsWf3551BWQzi4ksYJO390/9H0H3G/MSabI3rairYvHdkSdQF7/3PImT1k5PyREiJ/VrhYbLRaeSaF1rpAznzHfp3+MWGbjtJe7DBvuxu+Ob38I3Z4+hcGwxmqoioT3yF4vieahPmSHtv2sDrK3IiL5v2YTzleKA4k3+0J2gSQia8KCKECjsKKFsRYefCDM6YPpjs49/51ppV5YwA1GKbl9UtGh6bPwiypiT7FvpiGTBPa+TRJktw0CAwEAAaOBvDCBuTAOBgNVHQ8BAf8EBAMCBkAwgYcGCCsGAQUFBwEBBHsweTA5BggrBgEFBQcwAYYtaHR0cDovL2Rzcy5ub3dpbmEubHUvcGtpLWZhY3Rvcnkvb2NzcC9nb29kLWNhMDwGCCsGAQUFBzAChjBodHRwOi8vZHNzLm5vd2luYS5sdS9wa2ktZmFjdG9yeS9jcnQvZ29vZC1jYS5jcnQwHQYDVR0OBBYEFF6/dyhxBXMAMXBN7889SSzNgGvxMA0GCSqGSIb3DQEBCwUAA4IBAQCb9an2uzczD2dkyHMeZ9YI4cki9YOJ+3isdxdZG6ErlTvTb31zhOdQZOxhA9EpCwyG/It0nMTImJoUDJumixD0ZH/pyb0DeXyCgZbOVB4txxTKksRNbMvD6gKnIekJlfQEJnPIteyqp4EMZdcIZ105ud5lQ3c2Illl4FMjLkz+6QDI+8sN2hnVP43hImFwJfxng+pZeteD0Bhb0x7MD+jf9CL+1Ty0S7ZEoAgSlRKztJtoWfoFOxd+pepfYFlit7/muuqOLNdzj9P6zK4KAF6xM/ulHa77cHwroxpRYL9bhCZTk7sZGtWSfJZfvRH+shMzh4PPJGMAcsbDeVtpXvFZ");
		trustedListsCertificateSource.addCertificate(rootToken);
		
		CertificateVerifier certificateVerifier = getOfflineCertificateVerifier();

		certificateVerifier.setTrustedCertSource(trustedListsCertificateSource);
		validator.setCertificateVerifier(certificateVerifier);
		
		return validator;
	}
	
	@Override
	protected void checkBLevelValid(DiagnosticData diagnosticData) {
		assertFalse(diagnosticData.isBLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}
	
	@Override
	protected void checkSignatureScopes(DiagnosticData diagnosticData) {
		assertTrue(Utils.isCollectionEmpty(diagnosticData.getOriginalSignerDocuments()));
	}
	
	@Override
	protected void verifySimpleReport(SimpleReport simpleReport) {
		super.verifySimpleReport(simpleReport);

		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
	}
	
	@Override
	protected void validateETSISignerDocuments(List<SignersDocumentType> signersDocuments) {
		assertTrue(Utils.isCollectionEmpty(signersDocuments));
	}

}
