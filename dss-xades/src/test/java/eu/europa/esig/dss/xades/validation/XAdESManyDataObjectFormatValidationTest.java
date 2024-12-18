package eu.europa.esig.dss.xades.validation;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.validation.DocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Tag;

import java.util.ArrayList;
import java.util.List;

import static java.time.Duration.ofMillis;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTimeout;

@Tag("slow")
class XAdESManyDataObjectFormatValidationTest extends AbstractXAdESTestValidation {
    
    private static final List<DSSDocument> DETACHED_DOCUMENTS = new ArrayList<>();

    static {
        for (int i = 1; i <= 900; i++) {
            DETACHED_DOCUMENTS.add(new InMemoryDocument(String.format("test content %s", i).getBytes(), String.format("testFile_%s.txt", i)));
        }
    }

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/xades-900-references.xml");
    }

    @Override
    protected List<DSSDocument> getDetachedContents() {
        return DETACHED_DOCUMENTS;
    }

    @Override
    protected Reports validateDocument(DocumentValidator validator) {
        Reports reports = super.validateDocument(validator);

        List<AdvancedSignature> signatures = validator.getSignatures();
        assertEquals(1, signatures.size());

        assertTimeout(ofMillis(6000), () -> signatures.get(0).getDataFoundUpToLevel());

        return reports;
    }

}
