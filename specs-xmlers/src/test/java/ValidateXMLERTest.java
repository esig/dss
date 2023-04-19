import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.ers.xmlers.XMLEvidenceRecordFacade;
import eu.europa.esig.ers.xmlers.XMLEvidenceRecordUtils;

import eu.europa.esig.dss.model.TimestampBinary;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;

import eu.europa.esig.ers.xmlers.jaxb.ArchiveTimeStampSequenceType;
import eu.europa.esig.ers.xmlers.jaxb.ArchiveTimeStampType;
import eu.europa.esig.ers.xmlers.jaxb.EvidenceRecordType;
import eu.europa.esig.ers.xmlers.jaxb.HashTreeType;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.tsp.TSPException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeAll;
import org.xml.sax.SAXException;

import javax.xml.bind.JAXBException;
import javax.xml.stream.XMLStreamException;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

public class ValidateXMLERTest {

    private static XMLEvidenceRecordUtils xmlerUtils;

    @BeforeAll
    public static void init() {
        xmlerUtils = XMLEvidenceRecordUtils.getInstance();
    }

    public byte[] computeParent(byte[] input_1, byte[] input_2) throws IOException, NoSuchAlgorithmException {
        byte[] result;
        MessageDigest md = MessageDigest.getInstance("SHA-256");

        List<byte[]> list = new ArrayList<byte[]>();

        list.add(input_1);
        list.add(input_2);
        list.sort(new ByteArrayComparator());

        try(ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            for (byte[] byteArray : list) {
                baos.write(byteArray);
            }
            byte[] sorted_input_concatenated = baos.toByteArray();
            result = md.digest(sorted_input_concatenated);

            String encodeToString= Base64.getEncoder().encodeToString(result);
            System.out.println(encodeToString);
        }

        return result;
    }

    public byte[] getHashTreeRoot(List<byte[]> hashList) throws IOException, NoSuchAlgorithmException {

        byte[] hashParent = hashList.get(0);
        hashList.remove(0);

        for(byte[] hashNode : hashList){
            hashParent = computeParent(hashParent,hashNode);
        }

        return hashParent;
    }

    private void marshallUnmarshall(File file) throws JAXBException, XMLStreamException, IOException, SAXException {
        XMLEvidenceRecordFacade facade = XMLEvidenceRecordFacade.newFacade();

        EvidenceRecordType evidenceRecordType = facade.unmarshall(file);
        assertNotNull(evidenceRecordType);

        String marshall = facade.marshall(evidenceRecordType, true);
        assertNotNull(marshall);
    }

    @Test
    public void testXMLER() throws JAXBException, XMLStreamException, IOException, SAXException {
        marshallUnmarshall(new File("src/test/resources/ER_01.xml"));
    }

    @Test
    public void testVerifyER()throws IOException, NoSuchAlgorithmException, JAXBException, SAXException, XMLStreamException, CMSException, TSPException {
        boolean isValid = verifyERArchiveTimeStampMessageImprint(new File("src/test/resources/ER_01.xml"));
        assertEquals(isValid,true);
    }

    public boolean verifyERArchiveTimeStampMessageImprint(File xmlER) throws IOException, NoSuchAlgorithmException, JAXBException, SAXException, XMLStreamException, CMSException, TSPException {
        XMLEvidenceRecordFacade facade = XMLEvidenceRecordFacade.newFacade();

        EvidenceRecordType evidenceRecordType = facade.unmarshall(xmlER);

        // An XMLER only has one ArchiveTimesTampSequence, that is a list of ArchiveTimeStampChain
        List<ArchiveTimeStampSequenceType.ArchiveTimeStampChain> ATSCList = evidenceRecordType.getArchiveTimeStampSequence().getArchiveTimeStampChain();

        // An ArchiveTimeStampChain contains a list of ArchiveTimeStamp object.
        // Each ArchiveTimeStamp object encapsulates a reduced hash tree.
        // Each ArchiveTimeStamp object encapsulates an RFC3161 timestamp.
        // The messageImprint value of an RFC3161 timestamp in an ArchiveTimeStamp object must be match the value of the root of the corresponding reduced hash tree.
        for(ArchiveTimeStampSequenceType.ArchiveTimeStampChain ATSC : ATSCList){
            List<ArchiveTimeStampType> ATSList = ATSC.getArchiveTimeStamp();
            for(ArchiveTimeStampType ATS : ATSList){
                HashTreeType hashTree = ATS.getHashTree();
                List<HashTreeType.Sequence> sequenceList = hashTree.getSequence();
                List<byte[]> list = new ArrayList<byte[]>();
                for(HashTreeType.Sequence sequence : sequenceList){
                    List<byte[]> hashList = sequence.getDigestValue();
                    // We consider only a binary tree, as such there is always only one element in this hashList.
                    // If the tree is not a binary tree, everything breaks.
                    byte[] hash0 = hashList.get(0);
                    list.add(hash0);
                }
                System.out.println("=====Begin HashTree Root computation====");
                byte[] hashTreeRoot = getHashTreeRoot(list);
                System.out.println("=====End HashTree Root computation====");

                String timeStampValue = (String) ATS.getTimeStamp().getTimeStampToken().getContent().get(0);
                TimestampBinary timestampBinary = new TimestampBinary(Base64.getDecoder().decode(timeStampValue));
                TimestampToken timestampToken = new TimestampToken(Base64.getDecoder().decode(timeStampValue), TimestampType.ARCHIVE_TIMESTAMP);
                byte[] messageImprint = timestampToken.getMessageImprint().getValue();
                System.out.println("Timestamp messageImprint value is: "+ Base64.getEncoder().encodeToString(messageImprint));
                assertArrayEquals(hashTreeRoot,messageImprint);

                if (!Arrays.equals(messageImprint, hashTreeRoot)){
                    return false;
                }
            }
        }
        return true;
    }
    public class ByteArrayComparator implements Comparator<byte[]> {



        public int compare(byte[] left, byte[] right) {

            for (int i = 0, j = 0; i < left.length && j < right.length; i++, j++) {

                int a = (left[i] & 0xff);

                int b = (right[j] & 0xff);

                if (a != b) {

                    return a - b;

                }

            }

            return left.length - right.length;

        }

    }


}
