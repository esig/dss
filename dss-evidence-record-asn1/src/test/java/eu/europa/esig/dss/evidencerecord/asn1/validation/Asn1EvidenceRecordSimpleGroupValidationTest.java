//package eu.europa.esig.dss.evidencerecord.asn1.validation;
//
//import java.util.Arrays;
//import java.util.List;
//
//import eu.europa.esig.dss.enumerations.DigestAlgorithm;
//import eu.europa.esig.dss.evidencerecord.common.validation.AbstractEvidenceRecordTestValidation;
//import eu.europa.esig.dss.model.DSSDocument;
//import eu.europa.esig.dss.model.DigestDocument;
//import eu.europa.esig.dss.model.FileDocument;
//
//public class Asn1EvidenceRecordSimpleGroupValidationTest extends AbstractEvidenceRecordTestValidation {
//
//    @Override
//    protected DSSDocument getSignedDocument() {
//    	return new FileDocument("src/test/resources/evidencerecord.ers");
//    }
//
//    @Override
//    protected List<DSSDocument> getDetachedContents() {
//        return Arrays.asList(
//                new DigestDocument(DigestAlgorithm.SHA256, "EPRF0uQcTYjnF+PyR1a52z9fXpKZEAUx3d+jQAFfPos=", "1"),
//                new DigestDocument(DigestAlgorithm.SHA256, "Oida+g+rN0DmsVgqZOgAex7lYghgYcgQth4CXl5idH0=", "2"),
//                new DigestDocument(DigestAlgorithm.SHA256, "ZAiUg2B6CyVNPSiMgeaR4utRLwD3PPvMMBwXt0r3L7E=", "3"),
//                new DigestDocument(DigestAlgorithm.SHA256, "go+iO1ByVKxsnCPfTfTkZ9WYK45d52Dc7mrV1lUl6Ho=", "4"),
//                new DigestDocument(DigestAlgorithm.SHA256, "kG60U/JtBW9QHmxPX2+FH+I3q6FvtwS0G0kE1j6BT4Q=", "5"),
//                new DigestDocument(DigestAlgorithm.SHA256, "zFMwgPw86LH0Py/DPEAqMA3uqMgatCJe0UwKJxifjD8=", "6")
//        );
//    }
//
//}
