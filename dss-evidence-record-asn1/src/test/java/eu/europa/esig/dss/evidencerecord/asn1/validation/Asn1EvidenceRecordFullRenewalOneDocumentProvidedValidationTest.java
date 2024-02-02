package eu.europa.esig.dss.evidencerecord.asn1.validation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class Asn1EvidenceRecordFullRenewalOneDocumentProvidedValidationTest extends AbstractAsn1EvidenceRecordTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/er-asn1-full-renewal.ers");
    }

    @Override
    protected List<DSSDocument> getDetachedContents() {
        return Collections.singletonList(new InMemoryDocument("\u0003".getBytes()));
    }

    @Override
    protected void checkTimestamp(DiagnosticData diagnosticData, TimestampWrapper timestampWrapper) {
        assertNotNull(timestampWrapper.getProductionTime());
        assertTrue(timestampWrapper.isMessageImprintDataFound());
        assertTrue(timestampWrapper.isMessageImprintDataIntact());
        assertTrue(timestampWrapper.isSignatureIntact());
        assertTrue(timestampWrapper.isSignatureValid());

        List<XmlDigestMatcher> digestMatchers = timestampWrapper.getDigestMatchers();
        for (XmlDigestMatcher xmlDigestMatcher : digestMatchers) {
            if (DigestMatcherType.EVIDENCE_RECORD_ORPHAN_REFERENCE != xmlDigestMatcher.getType()) {
                assertTrue(xmlDigestMatcher.isDataFound());
                assertTrue(xmlDigestMatcher.isDataIntact());
            } else {
                assertFalse(xmlDigestMatcher.isDataFound());
                assertFalse(xmlDigestMatcher.isDataIntact());
            }
        }
        if (TimestampType.ARCHIVE_TIMESTAMP.equals(timestampWrapper.getType())) {
            assertNotNull(timestampWrapper.getArchiveTimestampType());
        }
    }

    @Override
    protected boolean allArchiveDataObjectsProvidedToValidation() {
        return false;
    }

    @Override
    protected boolean tstCoversOnlyCurrentHashTreeData() {
        return false;
    }

}
