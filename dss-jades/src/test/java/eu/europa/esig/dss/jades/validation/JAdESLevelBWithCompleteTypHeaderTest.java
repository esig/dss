package eu.europa.esig.dss.jades.validation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.validationreport.jaxb.SADataObjectFormatType;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class JAdESLevelBWithCompleteTypHeaderTest extends AbstractJAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/jades-level-b-full-type.json");
    }

    @Override
    protected void checkMimeType(DiagnosticData diagnosticData) {
        super.checkMimeType(diagnosticData);

        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertNotNull(signature.getMimeType());
        assertEquals(MimeType.JOSE, MimeType.fromMimeTypeString(signature.getMimeType()));
    }

    @Override
    protected void validateETSIDataObjectFormatType(SADataObjectFormatType dataObjectFormat) {
        super.validateETSIDataObjectFormatType(dataObjectFormat);

        assertNotNull(dataObjectFormat.getMimeType());
        assertEquals(MimeType.JOSE, MimeType.fromMimeTypeString(dataObjectFormat.getMimeType()));
    }

}
