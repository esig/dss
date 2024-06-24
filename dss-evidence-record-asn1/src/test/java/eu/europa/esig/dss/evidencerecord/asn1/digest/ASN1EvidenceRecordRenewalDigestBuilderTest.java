package eu.europa.esig.dss.evidencerecord.asn1.digest;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.evidencerecord.asn1.validation.ASN1EvidenceRecord;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import org.bouncycastle.asn1.tsp.EvidenceRecord;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ASN1EvidenceRecordRenewalDigestBuilderTest {

    @Test
    public void timeStampRenewalTest() {
        DSSDocument evidenceRecordDocument = new FileDocument("src/test/resources/er-asn1-simple.ers");

        ASN1EvidenceRecordRenewalDigestBuilder ASN1EvidenceRecordRenewalDigestBuilder = new ASN1EvidenceRecordRenewalDigestBuilder(evidenceRecordDocument);
        Digest digest = ASN1EvidenceRecordRenewalDigestBuilder.buildTimeStampRenewalDigest();
        assertEquals(DigestAlgorithm.SHA512, digest.getAlgorithm()); // original ArchiveTimeStampChain value is used
        assertEquals("7C8CB955697FAB1C876D260AC2760150BC8727C0F28F221A6BB5624B575A49A65F9E32D20A42A80A1C33C46E85BFC1460B34C538EB91930572C73C2E272983C7",
                digest.getHexValue());

        ASN1EvidenceRecordRenewalDigestBuilder = new ASN1EvidenceRecordRenewalDigestBuilder(evidenceRecordDocument, DigestAlgorithm.SHA256);

        digest = ASN1EvidenceRecordRenewalDigestBuilder.buildTimeStampRenewalDigest();
        assertEquals(DigestAlgorithm.SHA512, digest.getAlgorithm()); // original ArchiveTimeStampChain value is used
        assertEquals("7C8CB955697FAB1C876D260AC2760150BC8727C0F28F221A6BB5624B575A49A65F9E32D20A42A80A1C33C46E85BFC1460B34C538EB91930572C73C2E272983C7",
                digest.getHexValue());

        EvidenceRecord evidenceRecord = EvidenceRecord.getInstance(DSSUtils.toByteArray(evidenceRecordDocument));
        ASN1EvidenceRecord asn1EvidenceRecord = new ASN1EvidenceRecord(evidenceRecord);

        ASN1EvidenceRecordRenewalDigestBuilder = new ASN1EvidenceRecordRenewalDigestBuilder(asn1EvidenceRecord);
        digest = ASN1EvidenceRecordRenewalDigestBuilder.buildTimeStampRenewalDigest();
        assertEquals(DigestAlgorithm.SHA512, digest.getAlgorithm()); // original ArchiveTimeStampChain value is used
        assertEquals("7C8CB955697FAB1C876D260AC2760150BC8727C0F28F221A6BB5624B575A49A65F9E32D20A42A80A1C33C46E85BFC1460B34C538EB91930572C73C2E272983C7",
                digest.getHexValue());

        ASN1EvidenceRecordRenewalDigestBuilder = new ASN1EvidenceRecordRenewalDigestBuilder(asn1EvidenceRecord, DigestAlgorithm.SHA256);

        digest = ASN1EvidenceRecordRenewalDigestBuilder.buildTimeStampRenewalDigest();
        assertEquals(DigestAlgorithm.SHA512, digest.getAlgorithm()); // original ArchiveTimeStampChain value is used
        assertEquals("7C8CB955697FAB1C876D260AC2760150BC8727C0F28F221A6BB5624B575A49A65F9E32D20A42A80A1C33C46E85BFC1460B34C538EB91930572C73C2E272983C7",
                digest.getHexValue());
    }

    @Test
    public void hashTreeRenewalTest() {
        DSSDocument evidenceRecordDocument = new FileDocument("src/test/resources/er-asn1-simple.ers");

        ASN1EvidenceRecordRenewalDigestBuilder ASN1EvidenceRecordRenewalDigestBuilder = new ASN1EvidenceRecordRenewalDigestBuilder(evidenceRecordDocument);

        List<Digest> digestGroup = ASN1EvidenceRecordRenewalDigestBuilder.buildHashTreeRenewalDigestGroup();
        assertEquals(0, digestGroup.size()); // no detached data

        ASN1EvidenceRecordRenewalDigestBuilder = new ASN1EvidenceRecordRenewalDigestBuilder(evidenceRecordDocument, DigestAlgorithm.SHA512);

        digestGroup = ASN1EvidenceRecordRenewalDigestBuilder.buildHashTreeRenewalDigestGroup();
        assertEquals(0, digestGroup.size());

        List<DSSDocument> detachedContent = Collections.singletonList(new InMemoryDocument("1".getBytes()));

        ASN1EvidenceRecordRenewalDigestBuilder = new ASN1EvidenceRecordRenewalDigestBuilder(evidenceRecordDocument)
                .setDetachedContent(detachedContent);

        digestGroup = ASN1EvidenceRecordRenewalDigestBuilder.buildHashTreeRenewalDigestGroup();
        assertEquals(1, digestGroup.size());

        assertEquals(DigestAlgorithm.SHA256, digestGroup.get(0).getAlgorithm()); // original ArchiveTimeStampChain value is used
        assertEquals("EC365CD838E074CED4122687870A848CDE0B01BC150AC91B411EE93C6D31CBDA",
                digestGroup.get(0).getHexValue());

        ASN1EvidenceRecordRenewalDigestBuilder = new ASN1EvidenceRecordRenewalDigestBuilder(evidenceRecordDocument, DigestAlgorithm.SHA256)
                .setDetachedContent(detachedContent);

        digestGroup = ASN1EvidenceRecordRenewalDigestBuilder.buildHashTreeRenewalDigestGroup();
        assertEquals(1, digestGroup.size());

        assertEquals(DigestAlgorithm.SHA256, digestGroup.get(0).getAlgorithm()); // original ArchiveTimeStampChain value is used
        assertEquals("EC365CD838E074CED4122687870A848CDE0B01BC150AC91B411EE93C6D31CBDA",
                digestGroup.get(0).getHexValue());

        ASN1EvidenceRecordRenewalDigestBuilder = new ASN1EvidenceRecordRenewalDigestBuilder(evidenceRecordDocument, DigestAlgorithm.SHA512)
                .setDetachedContent(detachedContent);

        digestGroup = ASN1EvidenceRecordRenewalDigestBuilder.buildHashTreeRenewalDigestGroup();
        assertEquals(1, digestGroup.size());

        assertEquals(DigestAlgorithm.SHA512, digestGroup.get(0).getAlgorithm()); // original ArchiveTimeStampChain value is used
        assertEquals("2897511E559419E0EC02D6F03CFE3AD18598CD1A9483C17E87375805336FE5A4D50F9470E7CEB087948F4D4FE7BC730E62F03AEE5E728562600E344470755F34",
                digestGroup.get(0).getHexValue());


        EvidenceRecord evidenceRecord = EvidenceRecord.getInstance(DSSUtils.toByteArray(evidenceRecordDocument));
        ASN1EvidenceRecord asn1EvidenceRecord = new ASN1EvidenceRecord(evidenceRecord);

        ASN1EvidenceRecordRenewalDigestBuilder = new ASN1EvidenceRecordRenewalDigestBuilder(asn1EvidenceRecord);

        digestGroup = ASN1EvidenceRecordRenewalDigestBuilder.buildHashTreeRenewalDigestGroup();
        assertEquals(0, digestGroup.size()); // no detached data

        ASN1EvidenceRecordRenewalDigestBuilder = new ASN1EvidenceRecordRenewalDigestBuilder(asn1EvidenceRecord, DigestAlgorithm.SHA512);

        digestGroup = ASN1EvidenceRecordRenewalDigestBuilder.buildHashTreeRenewalDigestGroup();
        assertEquals(0, digestGroup.size());

        ASN1EvidenceRecordRenewalDigestBuilder = new ASN1EvidenceRecordRenewalDigestBuilder(asn1EvidenceRecord)
                .setDetachedContent(detachedContent);

        digestGroup = ASN1EvidenceRecordRenewalDigestBuilder.buildHashTreeRenewalDigestGroup();
        assertEquals(1, digestGroup.size());

        assertEquals(DigestAlgorithm.SHA256, digestGroup.get(0).getAlgorithm()); // original ArchiveTimeStampChain value is used
        assertEquals("EC365CD838E074CED4122687870A848CDE0B01BC150AC91B411EE93C6D31CBDA",
                digestGroup.get(0).getHexValue());

        ASN1EvidenceRecordRenewalDigestBuilder = new ASN1EvidenceRecordRenewalDigestBuilder(asn1EvidenceRecord, DigestAlgorithm.SHA256)
                .setDetachedContent(detachedContent);

        digestGroup = ASN1EvidenceRecordRenewalDigestBuilder.buildHashTreeRenewalDigestGroup();
        assertEquals(1, digestGroup.size());

        assertEquals(DigestAlgorithm.SHA256, digestGroup.get(0).getAlgorithm()); // original ArchiveTimeStampChain value is used
        assertEquals("EC365CD838E074CED4122687870A848CDE0B01BC150AC91B411EE93C6D31CBDA",
                digestGroup.get(0).getHexValue());

        ASN1EvidenceRecordRenewalDigestBuilder = new ASN1EvidenceRecordRenewalDigestBuilder(asn1EvidenceRecord, DigestAlgorithm.SHA512)
                .setDetachedContent(detachedContent);

        digestGroup = ASN1EvidenceRecordRenewalDigestBuilder.buildHashTreeRenewalDigestGroup();
        assertEquals(1, digestGroup.size());

        assertEquals(DigestAlgorithm.SHA512, digestGroup.get(0).getAlgorithm()); // original ArchiveTimeStampChain value is used
        assertEquals("2897511E559419E0EC02D6F03CFE3AD18598CD1A9483C17E87375805336FE5A4D50F9470E7CEB087948F4D4FE7BC730E62F03AEE5E728562600E344470755F34",
                digestGroup.get(0).getHexValue());
    }

    @Test
    public void nullTest() {
        Exception exception = assertThrows(NullPointerException.class, () -> new ASN1EvidenceRecordRenewalDigestBuilder((DSSDocument) null));
        assertEquals("Document cannot be null!", exception.getMessage());

        exception = assertThrows(NullPointerException.class, () -> new ASN1EvidenceRecordRenewalDigestBuilder((ASN1EvidenceRecord) null));
        assertEquals("EvidenceRecord cannot be null!", exception.getMessage());

        DSSDocument evidenceRecordDocument = new FileDocument("src/test/resources/er-asn1-simple.ers");

        exception = assertThrows(NullPointerException.class, () -> new ASN1EvidenceRecordRenewalDigestBuilder(evidenceRecordDocument, null));
        assertEquals("DigestAlgorithm cannot be null!", exception.getMessage());

        EvidenceRecord evidenceRecord = EvidenceRecord.getInstance(DSSUtils.toByteArray(evidenceRecordDocument));
        ASN1EvidenceRecord asn1EvidenceRecord = new ASN1EvidenceRecord(evidenceRecord);
        exception = assertThrows(NullPointerException.class, () -> new ASN1EvidenceRecordRenewalDigestBuilder(asn1EvidenceRecord, null));
        assertEquals("DigestAlgorithm cannot be null!", exception.getMessage());
    }

    @Test
    public void invalidFormatTest() {
        Exception exception = assertThrows(IllegalInputException.class, () ->
                new ASN1EvidenceRecordRenewalDigestBuilder(new FileDocument("src/test/resources/Signature-C-LT.p7m")));
        assertTrue(exception.getMessage().contains("An ASN.1 file is expected"));

        exception = assertThrows(IllegalInputException.class, () ->
                new ASN1EvidenceRecordRenewalDigestBuilder(new FileDocument("src/test/resources/er-simple.xml")));
        assertTrue(exception.getMessage().contains("An ASN.1 file is expected"));
    }

}
