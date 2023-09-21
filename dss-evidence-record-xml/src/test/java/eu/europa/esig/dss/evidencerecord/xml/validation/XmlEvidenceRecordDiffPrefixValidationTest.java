package eu.europa.esig.dss.evidencerecord.xml.validation;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.evidencerecord.common.validation.AbstractEvidenceRecordTestValidation;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.FileDocument;

import java.util.Arrays;
import java.util.List;

public class XmlEvidenceRecordDiffPrefixValidationTest extends AbstractEvidenceRecordTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/er-diff-prefix.xml");
    }

    @Override
    protected List<DSSDocument> getDetachedContents() {
        return Arrays.asList(
                new DigestDocument(DigestAlgorithm.SHA256, "MpVJQIYeSHwy2BZBjp7hlzzRYzJ2ijY05vfW0yS0OsY=", "CIAO"),
                new DigestDocument(DigestAlgorithm.SHA256, "gTKownnX+TP6TAxAhrcOHbPZ0LjUnPbD11GrTQECVOU=", "HELLO")
        );
    }

}
