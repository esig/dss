package eu.europa.esig.dss.cms.stream.signature;

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.signature.AbstractCAdESTestSignature;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.cades.signature.CAdESTimestampParameters;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.signature.resources.TempFileResourcesHandlerBuilder;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

@Tag("slow")
class CAdESDoubleLTALargeFileTest extends AbstractCAdESTestSignature {

    private DSSDocument documentToSign;
    private CAdESSignatureParameters parameters;
    private CAdESService service;

    @BeforeEach
    void init() throws IOException {
        documentToSign = generateLargeFile();

        parameters = new CAdESSignatureParameters();
        parameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        parameters.setSigningCertificate(getSigningCert());
        parameters.setCertificateChain(getCertificateChain());
        parameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LTA);
        parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);

        CAdESTimestampParameters archiveTimeStampParameters = new CAdESTimestampParameters();
        archiveTimeStampParameters.setDigestAlgorithm(DigestAlgorithm.SHA384);
        parameters.setArchiveTimestampParameters(archiveTimeStampParameters);

        service = new CAdESService(getCompleteCertificateVerifier());
        service.setResourcesHandlerBuilder(new TempFileResourcesHandlerBuilder());
        service.setTspSource(getGoodTsa());
    }

    private DSSDocument generateLargeFile() throws IOException {
        File file = new File("target/large-binary.bin");

        long size = 0x00FFFFFF; // Integer.MAX_VALUE -1
        byte [] data = new byte[(int)size];
        SecureRandom sr = new SecureRandom();
        sr.nextBytes(data);

        try (FileOutputStream fos = new FileOutputStream(file)) {
            for (int i = 0; i < 500; i++) {
                fos.write(data);
            }
        }

        return new FileDocument(file);
    }

    @Test
    @Override
    public void signAndVerify() {
        DSSDocument signed = sign();

        DSSDocument doubleLtaDoc = service.extendDocument(signed, parameters);

        assertNotNull(doubleLtaDoc.getName());
        assertNotNull(doubleLtaDoc.getMimeType());

        checkMimeType(doubleLtaDoc);

        Reports reports = verify(doubleLtaDoc);

        DiagnosticData diagnosticData = reports.getDiagnosticData();

        assertEquals(SignatureLevel.CAdES_BASELINE_LTA, diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
        assertEquals(3, diagnosticData.getTimestampIdList(diagnosticData.getFirstSignatureId()).size());
    }

    @Override
    protected void verifyOriginalDocuments(SignedDocumentValidator validator, DiagnosticData diagnosticData) {
        // skip
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

    @Override
    protected DSSDocument getDocumentToSign() {
        return documentToSign;
    }

    @Override
    protected DocumentSignatureService<CAdESSignatureParameters, CAdESTimestampParameters> getService() {
        return service;
    }

    @Override
    protected CAdESSignatureParameters getSignatureParameters() {
        return parameters;
    }

}
