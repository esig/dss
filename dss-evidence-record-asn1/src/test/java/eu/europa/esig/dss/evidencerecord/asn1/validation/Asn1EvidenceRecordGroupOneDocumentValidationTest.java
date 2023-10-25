//package eu.europa.esig.dss.evidencerecord.asn1.validation;
//
//import java.util.Collections;
//import java.util.List;
//
//import eu.europa.esig.dss.enumerations.DigestAlgorithm;
//import eu.europa.esig.dss.evidencerecord.common.validation.AbstractEvidenceRecordTestValidation;
//import eu.europa.esig.dss.model.DSSDocument;
//import eu.europa.esig.dss.model.DigestDocument;
//import eu.europa.esig.dss.model.FileDocument;
//
//public class Asn1EvidenceRecordGroupOneDocumentValidationTest extends AbstractEvidenceRecordTestValidation {
//
//    @Override
//    protected DSSDocument getSignedDocument() {
//    	return new FileDocument("src/test/resources/evidencerecord.ers");
//    }
//
//    @Override
//    protected List<DSSDocument> getDetachedContents() {
//    	return Collections.singletonList(new DigestDocument(DigestAlgorithm.SHA256, "Oida+g+rN0DmsVgqZOgAex7lYghgYcgQth4CXl5idH0="));
//    }
//
//}
