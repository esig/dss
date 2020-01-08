package eu.europa.esig.dss.pades.signature.suite;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.Collections;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.BLevelParameters;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.TimestampParameters;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pades.CertificationPermission;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.test.signature.PKIFactoryAccess;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

public class PAdESServiceTest extends PKIFactoryAccess {
	
	private static DSSDocument documentToSign;
	private static PAdESService service;
	
	@BeforeEach
	public void init() {
		documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/sample.pdf"), "sample.pdf", MimeType.PDF);
        service = new PAdESService(getCompleteCertificateVerifier());
        service.setTspSource(getGoodTsa());
	}
	
	@Test
	public void testSignature() throws Exception {
		PAdESSignatureParameters signatureParameters = new PAdESSignatureParameters();
		
        Exception exception = assertThrows(NullPointerException.class, () -> signAndValidate(null, signatureParameters));
        assertEquals("toSignDocument cannot be null!", exception.getMessage());
		
        exception = assertThrows(NullPointerException.class, () -> signAndValidate(documentToSign, null));
        assertEquals("SignatureParameters cannot be null!", exception.getMessage());
		
        exception = assertThrows(DSSException.class, () -> signAndValidate(documentToSign, signatureParameters));
        assertEquals("Signing Certificate is not defined!", exception.getMessage());
        
        signatureParameters.setGenerateTBSWithoutCertificate(true);
        exception = assertThrows(NullPointerException.class, () -> signAndValidate(documentToSign, signatureParameters));
        assertEquals("SignatureLevel must be defined!", exception.getMessage());
        signatureParameters.setGenerateTBSWithoutCertificate(false);

        signatureParameters.setSignWithExpiredCertificate(true);
        exception = assertThrows(DSSException.class, () -> signAndValidate(documentToSign, signatureParameters));
        assertEquals("Signing Certificate is not defined!", exception.getMessage());
        
        signatureParameters.setSigningCertificate(getSigningCert());
        exception = assertThrows(NullPointerException.class, () -> signAndValidate(documentToSign, signatureParameters));
        assertEquals("SignatureLevel must be defined!", exception.getMessage());
        
        exception = assertThrows(IllegalArgumentException.class, () -> signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B));
        assertEquals("Only PAdES form is allowed !", exception.getMessage());
        
        signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
        signAndValidate(documentToSign, signatureParameters);
        
        exception = assertThrows(NullPointerException.class, () -> signatureParameters.bLevel().setSigningDate(null));
        assertEquals("SigningDate cannot be null!", exception.getMessage());

        signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LTA);
        signAndValidate(documentToSign, signatureParameters);
        
        signatureParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
        signAndValidate(documentToSign, signatureParameters);
        
        signatureParameters.setArchiveTimestampParameters(new TimestampParameters());
        signAndValidate(documentToSign, signatureParameters);
        
        signatureParameters.setBLevelParams(new BLevelParameters());
        signAndValidate(documentToSign, signatureParameters);
        
        signatureParameters.setCertificateChain(Collections.emptyList());
        signAndValidate(documentToSign, signatureParameters);
        
        signatureParameters.setCertificateChain((List<CertificateToken>)null);
        signAndValidate(documentToSign, signatureParameters);
        
        signatureParameters.setContentTimestampParameters(new TimestampParameters());
        signAndValidate(documentToSign, signatureParameters);
        
        signatureParameters.setDetachedContents(Collections.emptyList());
        signAndValidate(documentToSign, signatureParameters);
        
        signatureParameters.setSignatureTimestampParameters(new TimestampParameters());
        signAndValidate(documentToSign, signatureParameters);
        
        signatureParameters.setSignedData(new byte[] {});
        signAndValidate(documentToSign, signatureParameters);
        
        exception = assertThrows(NullPointerException.class, () -> signatureParameters.setDigestAlgorithm(null));
        assertEquals("DigestAlgorithm cannot be null!", exception.getMessage());
        
        signatureParameters.setReason(Utils.EMPTY_STRING);
        signAndValidate(documentToSign, signatureParameters);
        
        signatureParameters.setContactInfo(Utils.EMPTY_STRING);
        signAndValidate(documentToSign, signatureParameters);
        
        signatureParameters.setLocation(Utils.EMPTY_STRING);
        signAndValidate(documentToSign, signatureParameters);
        
        signatureParameters.setSignatureFieldId(Utils.EMPTY_STRING);
        signAndValidate(documentToSign, signatureParameters);
        
        signatureParameters.setSignatureSize(1);
		signatureParameters.setTimestampSize(1);
        exception = assertThrows(DSSException.class, () -> signAndValidate(documentToSign, signatureParameters));

        signatureParameters.setSignatureSize(8192);
		signatureParameters.setTimestampSize(8192);
        signatureParameters.setSignatureFilter(null);
        signAndValidate(documentToSign, signatureParameters);
        
        signatureParameters.setSignatureFilter(Utils.EMPTY_STRING);
        signAndValidate(documentToSign, signatureParameters);
        
        signatureParameters.setSignatureSubFilter(null);
        signAndValidate(documentToSign, signatureParameters);
        
        signatureParameters.setSignatureSubFilter(Utils.EMPTY_STRING);
        signAndValidate(documentToSign, signatureParameters);
        
        signatureParameters.setSignerName(Utils.EMPTY_STRING);
        signAndValidate(documentToSign, signatureParameters);
        
        signatureParameters.setSignatureImageParameters(new SignatureImageParameters());
        exception = assertThrows(DSSException.class, () -> signAndValidate(documentToSign, signatureParameters));
        assertTrue(exception.getMessage().contains("Neither image nor text parameters are defined!"));

        signatureParameters.setSignatureImageParameters(null);
        signatureParameters.setTimestampFilter(null);
        signAndValidate(documentToSign, signatureParameters);
        
        signatureParameters.setTimestampFilter(Utils.EMPTY_STRING);
        signAndValidate(documentToSign, signatureParameters);
        
        signatureParameters.setTimestampSubFilter(null);
        signAndValidate(documentToSign, signatureParameters);
        
        signatureParameters.setTimestampSubFilter(Utils.EMPTY_STRING);
        signAndValidate(documentToSign, signatureParameters);
        
        signatureParameters.setTimestampImageParameters(new SignatureImageParameters());
        exception = assertThrows(DSSException.class, () -> signAndValidate(documentToSign, signatureParameters));
        assertTrue(exception.getMessage().contains("Neither image nor text parameters are defined!"));

        signatureParameters.setTimestampImageParameters(null);
        signatureParameters.setPermission(CertificationPermission.NO_CHANGE_PERMITTED);
        signAndValidate(documentToSign, signatureParameters);
	}
	
	private DSSDocument signAndValidate(DSSDocument documentToSign, PAdESSignatureParameters signatureParameters) {
        ToBeSigned dataToSign = service.getDataToSign(documentToSign, signatureParameters);
        SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
        DSSDocument signedDocument = service.signDocument(documentToSign, signatureParameters, signatureValue);
        assertNotNull(signedDocument);
        validate(signedDocument);
        return signedDocument;
	}
	
	@Test
	public void testExtension() throws IOException {
		PAdESSignatureParameters signatureParameters = new PAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
		DSSDocument signedDocument = signAndValidate(documentToSign, signatureParameters);
		signedDocument.save("target/signed.pdf");
		
		PAdESSignatureParameters extensionParameters = new PAdESSignatureParameters();
		
        Exception exception = assertThrows(NullPointerException.class, () -> extendAndValidate(null, extensionParameters));
        assertEquals("toExtendDocument is not defined!", exception.getMessage());
		
        exception = assertThrows(NullPointerException.class, () -> extendAndValidate(signedDocument, null));
        assertEquals("Cannot extend the signature. SignatureParameters are not defined!", exception.getMessage());

        exception = assertThrows(NullPointerException.class, () -> extendAndValidate(signedDocument, extensionParameters));
        assertEquals("SignatureLevel must be defined!", exception.getMessage());

        exception = assertThrows(IllegalArgumentException.class, () -> extensionParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B));
        assertEquals("Only PAdES form is allowed !", exception.getMessage());
        
        extensionParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
        exception = assertThrows(IllegalArgumentException.class, () -> extendAndValidate(signedDocument, extensionParameters));
        assertEquals("Cannot extend to PAdES_BASELINE_B", exception.getMessage());
        
        extensionParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LTA);
        extendAndValidate(signedDocument, extensionParameters);
	}
	
	private DSSDocument extendAndValidate(DSSDocument documentToExtend, PAdESSignatureParameters signatureParameters) {
		DSSDocument extendedDocument = service.extendDocument(documentToExtend, signatureParameters);
        assertNotNull(extendedDocument);
        validate(extendedDocument);
        return extendedDocument;
	}
	
	private void validate(DSSDocument documentToValidate) {
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(documentToValidate);
        validator.setCertificateVerifier(getCompleteCertificateVerifier());
        Reports reports = validator.validateDocument();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        
        DiagnosticData diagnosticData = reports.getDiagnosticData();
        List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
        for (TimestampWrapper timestamp : timestampList) {
        	assertTrue(timestamp.isSignatureValid());
        	assertTrue(timestamp.isSignatureIntact());
        	assertTrue(timestamp.isMessageImprintDataFound());
        	assertTrue(timestamp.isMessageImprintDataIntact());
        }
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
