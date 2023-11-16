package eu.europa.esig.dss.evidencerecord.asn1.validation;

import java.util.Collections;
import java.util.List;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.evidencerecord.common.validation.AbstractEvidenceRecordTestValidation;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.FileDocument;

public class Asn1EvidenceRecordUncommonChainRenewalValidationTest extends AbstractEvidenceRecordTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
    	return new FileDocument("src/test/resources/LKSG_4.ers");
    }

    protected List<DSSDocument> getDetachedContents() {
        DigestDocument digestDocument = new DigestDocument();
        digestDocument.setName("LKSG_4.pdf");
        digestDocument.addDigest(DigestAlgorithm.SHA256, "SMP/0kaannOThgfDF1Dly2qUG2Zbj5YMyNLSRZHWkO0=");
        digestDocument.addDigest(DigestAlgorithm.SHA384, "EfWPNqRRVrdEffJtLzF/l13oPz9qGQ5IR/sbRZxglqIzS95wy128Yi/KBEGKaIIX");
        return Collections.singletonList(digestDocument);
    }

    @Override
    protected boolean allArchiveDataObjectsProvidedToValidation() {
        // only one document is covered over all chains
        return false;
    }

    @Override
    protected boolean tstCoversOnlyCurrentHashTreeData() {
        // ArchiveTimeStamp covers also two additional data objects
        return false;
    }
}
