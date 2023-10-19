package eu.europa.esig.dss.evidencerecord.asn1.validation;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.evidencerecord.common.validation.AbstractEvidenceRecordTestValidation;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public class Asn1EvidenceRecordSimpleValidationValidationTest extends AbstractEvidenceRecordTestValidation {

//    @Override
//    protected DSSDocument getSignedDocument() {
//        //return new FileDocument("src/test/resources/M3_06_step04_003_0fdaf7a1-401c-4608-ae01-c605ddc1c8b2_0.asn1.ers");
//    	//return new FileDocument("src/test/resources/bsi_gov_vte-lza_002.ers");
//    	return new FileDocument("src/test/resources/BIN-1_ER.ers");
//    }

//    @Override
//    protected List<DSSDocument> getDetachedContents() {
//        //return Collections.singletonList(new DigestDocument(DigestAlgorithm.SHA256, "uzXrCRois1VCTQ3h9pWcaYzmKAJX8ClAMMOGns8D9kU="));
//    	//return Collections.singletonList(new DigestDocument(DigestAlgorithm.SHA256, "APwdp+9Oaz6IpUdL4YLc6HG2d9TwDuxFzlNvwiRrFT8="));
//    	//return Collections.singletonList(new DigestDocument(DigestAlgorithm.SHA256, "odTntQ2Wk/mjGy6UhOpq36WFg3cw/iupTROl1MgcMt8="));
//        return Arrays.asList(
//                new DigestDocument(DigestAlgorithm.SHA256, "odTntQ2Wk/mjGy6UhOpq36WFg3cw/iupTROl1MgcMt8=", "some binary content"),
//                new DigestDocument(DigestAlgorithm.SHA256, "2Eg+KWYIINZGWWKP1rUlW4zrtlKk5Ws2VEVJA6fSSgQ=", "some binary content")
//        );
//    }
//    

    @Override
    protected DSSDocument getSignedDocument() {
    	return new FileDocument("src/test/resources/BIN-3_ER.ers");
    }

    @Override
    protected List<DSSDocument> getDetachedContents() {
        return Collections.singletonList(new InMemoryDocument("da2e47f2-53f4-4610-8210-f0f05d67d0c9".getBytes()));
    }


}
