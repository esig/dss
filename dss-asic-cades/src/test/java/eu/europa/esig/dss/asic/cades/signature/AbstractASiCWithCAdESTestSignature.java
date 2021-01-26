package eu.europa.esig.dss.asic.cades.signature;

import eu.europa.esig.dss.asic.cades.ASiCWithCAdESContainerExtractor;
import eu.europa.esig.dss.asic.cades.ASiCWithCAdESSignatureParameters;
import eu.europa.esig.dss.asic.cades.ASiCWithCAdESTimestampParameters;
import eu.europa.esig.dss.asic.common.ASiCExtractResult;
import eu.europa.esig.dss.asic.common.signature.AbstractASiCTestSignature;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.validationreport.jaxb.SignatureIdentifierType;
import eu.europa.esig.validationreport.jaxb.SignatureValidationReportType;
import eu.europa.esig.validationreport.jaxb.ValidationReportType;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public abstract class AbstractASiCWithCAdESTestSignature
        extends AbstractASiCTestSignature<ASiCWithCAdESSignatureParameters, ASiCWithCAdESTimestampParameters> {

    @Override
    protected List<DSSDocument> getOriginalDocuments() {
        return Collections.singletonList(getDocumentToSign());
    }

    @Override
    protected boolean isBaselineT() {
        SignatureLevel signatureLevel = getSignatureParameters().getSignatureLevel();
        return SignatureLevel.CAdES_BASELINE_LTA.equals(signatureLevel) || SignatureLevel.CAdES_BASELINE_LT.equals(signatureLevel)
                || SignatureLevel.CAdES_BASELINE_T.equals(signatureLevel);
    }

    @Override
    protected boolean isBaselineLTA() {
        return SignatureLevel.CAdES_BASELINE_LTA.equals(getSignatureParameters().getSignatureLevel());
    }

    @Override
    protected void onDocumentSigned(byte[] byteArray) {
        super.onDocumentSigned(byteArray);

        ASiCWithCAdESContainerExtractor containerExtractor = new ASiCWithCAdESContainerExtractor(new InMemoryDocument(byteArray));
        ASiCExtractResult result = containerExtractor.extract();

        List<DSSDocument> signatureDocuments = result.getSignatureDocuments();
        assertTrue(Utils.isCollectionNotEmpty(signatureDocuments));
        for (DSSDocument signatureDocument : signatureDocuments) {
            // validate with no detached content
            DiagnosticData diagnosticData = validateDocument(signatureDocument);
            SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
            List<XmlDigestMatcher> digestMatchers = signature.getDigestMatchers();
            assertEquals(1, digestMatchers.size());
            assertFalse(digestMatchers.get(0).isDataFound());
            assertFalse(digestMatchers.get(0).isDataIntact());

            // with detached content
            diagnosticData = validateDocument(signatureDocument, Arrays.asList(getSignedData(result)));
            signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
            digestMatchers = signature.getDigestMatchers();
            assertEquals(1, digestMatchers.size());
            assertTrue(digestMatchers.get(0).isDataFound());
            assertTrue(digestMatchers.get(0).isDataIntact());
        }
    }

    protected abstract DSSDocument getSignedData(ASiCExtractResult extractResult);

    private DiagnosticData validateDocument(DSSDocument signatureDocument) {
        return validateDocument(signatureDocument, null);
    }

    private DiagnosticData validateDocument(DSSDocument signatureDocument, List<DSSDocument> detachedContents) {
        SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signatureDocument);
        validator.setCertificateVerifier(getOfflineCertificateVerifier());
        if (Utils.isCollectionNotEmpty(detachedContents)) {
            validator.setDetachedContents(detachedContents);
        }
        Reports reports = validator.validateDocument();
        return reports.getDiagnosticData();
    }

    @Override
    protected void checkContainerInfo(DiagnosticData diagnosticData) {
        assertNotNull(diagnosticData.getContainerInfo());
        assertEquals(getExpectedASiCContainerType(), diagnosticData.getContainerType());
        assertNotNull(diagnosticData.getMimetypeFileContent());
        assertTrue(Utils.isCollectionNotEmpty(diagnosticData.getContainerInfo().getContentFiles()));
    }

    protected abstract ASiCContainerType getExpectedASiCContainerType();

    @Override
    protected void checkSignatureIdentifier(DiagnosticData diagnosticData) {
        for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
            assertNotNull(signatureWrapper.getSignatureValue());
        }
    }

    @Override
    protected void checkReportsSignatureIdentifier(Reports reports) {
        DiagnosticData diagnosticData = reports.getDiagnosticData();
        ValidationReportType etsiValidationReport = reports.getEtsiValidationReportJaxb();

        if (Utils.isCollectionNotEmpty(diagnosticData.getSignatures())) {
            for (SignatureValidationReportType signatureValidationReport : etsiValidationReport.getSignatureValidationReport()) {
                SignatureWrapper signature = diagnosticData.getSignatureById(signatureValidationReport.getSignatureIdentifier().getId());

                SignatureIdentifierType signatureIdentifier = signatureValidationReport.getSignatureIdentifier();
                assertNotNull(signatureIdentifier);

                assertNotNull(signatureIdentifier.getSignatureValue());
                assertTrue(Arrays.equals(signature.getSignatureValue(), signatureIdentifier.getSignatureValue().getValue()));
            }
        }
    }

}
