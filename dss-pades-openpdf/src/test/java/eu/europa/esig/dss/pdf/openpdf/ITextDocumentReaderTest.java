package eu.europa.esig.dss.pdf.openpdf;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ITextDocumentReaderTest {

    @Test
    public void permissionsSimpleDocument() throws IOException {
        DSSDocument dssDocument = new InMemoryDocument(getClass().getResourceAsStream("/sample.pdf"));
        try (ITextDocumentReader documentReader = new ITextDocumentReader(dssDocument)) {
            assertFalse(documentReader.isEncrypted());
            assertTrue(documentReader.isOpenWithOwnerAccess());
            assertTrue(documentReader.canFillSignatureForm());
            assertTrue(documentReader.canCreateSignatureField());
        }
    }

    @Test
    public void permissionsProtectedDocument() throws IOException {
        DSSDocument dssDocument = new InMemoryDocument(getClass().getResourceAsStream("/protected/open_protected.pdf"));
        try (ITextDocumentReader documentReader = new ITextDocumentReader(dssDocument, new byte[]{ ' ' })) {
            assertTrue(documentReader.isEncrypted());
            assertTrue(documentReader.isOpenWithOwnerAccess());
            assertTrue(documentReader.canFillSignatureForm());
            assertTrue(documentReader.canCreateSignatureField());
        }
    }

    @Test
    public void permissionsEditionProtectedDocument() throws IOException {
        DSSDocument dssDocument = new InMemoryDocument(getClass().getResourceAsStream("/protected/edition_protected_none.pdf"));
        try (ITextDocumentReader documentReader = new ITextDocumentReader(dssDocument, new byte[]{ ' ' })) {
            assertTrue(documentReader.isEncrypted());
            assertTrue(documentReader.isOpenWithOwnerAccess());
            assertTrue(documentReader.canFillSignatureForm());
            assertTrue(documentReader.canCreateSignatureField());
        }
    }

    @Test
    public void permissionsEditionNoFieldsProtectedDocument() throws IOException {
        DSSDocument dssDocument = new InMemoryDocument(getClass().getResourceAsStream("/protected/edition_protected_signing_allowed_no_field.pdf"));
        try (ITextDocumentReader documentReader = new ITextDocumentReader(dssDocument, new byte[]{ ' ' })) {
            assertTrue(documentReader.isEncrypted());
            assertTrue(documentReader.isOpenWithOwnerAccess());
            assertTrue(documentReader.canFillSignatureForm());
            assertTrue(documentReader.canCreateSignatureField());
        }
    }

}
