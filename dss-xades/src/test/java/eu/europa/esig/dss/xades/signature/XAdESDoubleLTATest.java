package eu.europa.esig.dss.xades.signature;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import org.junit.Test;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.ArchiveTimestampType;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.test.signature.PKIFactoryAccess;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;

public class XAdESDoubleLTATest extends PKIFactoryAccess {
	
	@Test
	public void test() throws IOException {
		DSSDocument documentToSign = new FileDocument("src/test/resources/sample.xml");

        XAdESSignatureParameters signatureParameters = new XAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(new Date());
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LT);
		signatureParameters.setSignaturePackaging(SignaturePackaging.DETACHED);

        XAdESService service = new XAdESService(getCompleteCertificateVerifier());
        service.setTspSource(getGoodTsa());

        ToBeSigned dataToSign = service.getDataToSign(documentToSign, signatureParameters);
        SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
        DSSDocument signedDocument = service.signDocument(documentToSign, signatureParameters, signatureValue);

        // signedDocument.save("target/signed.xml");

        service.setTspSource(getGoodTsaCrossCertification());

        XAdESSignatureParameters extendParameters = new XAdESSignatureParameters();
        extendParameters.setDetachedContents(Arrays.asList(documentToSign));
        extendParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LTA);
        DSSDocument extendedDocument = service.extendDocument(signedDocument, extendParameters);
        
        DSSDocument doubleLTADoc = service.extendDocument(extendedDocument, extendParameters);
        
        // doubleLTADoc.save("target/doubleLTA.xml");
        
        SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doubleLTADoc);
        validator.setCertificateVerifier(getOfflineCertificateVerifier());
        validator.setDetachedContents(Arrays.asList(documentToSign));
        Reports reports = validator.validateDocument();
        
        // reports.print();
        
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        
        DetailedReport detailedReport = reports.getDetailedReport();
        List<String> timestampIds = detailedReport.getTimestampIds();
        assertEquals(3, timestampIds.size());
        
        DiagnosticData diagnosticData = reports.getDiagnosticData();
        
        int archiveTimestampCounter = 0;
        for (String id : timestampIds) {
            assertEquals(Indication.PASSED, detailedReport.getTimestampValidationIndication(id));
            TimestampWrapper timestamp = diagnosticData.getTimestampById(id);
            if (TimestampType.ARCHIVE_TIMESTAMP.equals(timestamp.getType())) {
            	assertEquals(ArchiveTimestampType.XAdES_141, timestamp.getArchiveTimestampType());
            	archiveTimestampCounter++;
            }
        }
        assertEquals(2, archiveTimestampCounter);
        
        List<CertificateWrapper> usedCertificates = diagnosticData.getUsedCertificates();
        for (CertificateWrapper certificate : usedCertificates) {
        	assertTrue("Certificate with id : [" + certificate.getId() + "] does not have a revocation data!", 
        			certificate.isRevocationDataAvailable() || certificate.isTrusted() || certificate.isSelfSigned());
        }
        
	}

	@Override
	protected String getSigningAlias() {
		return RSA_SHA3_USER;
	}

}
