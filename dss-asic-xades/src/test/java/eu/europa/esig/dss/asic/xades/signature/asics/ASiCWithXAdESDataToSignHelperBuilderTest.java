package eu.europa.esig.dss.asic.xades.signature.asics;

import eu.europa.esig.dss.asic.xades.ASiCWithXAdESSignatureParameters;
import eu.europa.esig.dss.asic.xades.signature.ASiCWithXAdESDataToSignHelperBuilder;
import eu.europa.esig.dss.asic.xades.signature.GetDataToSignASiCWithXAdESHelper;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ASiCWithXAdESDataToSignHelperBuilderTest {

    private static final Logger LOG = LoggerFactory.getLogger(ASiCWithXAdESDataToSignHelperBuilderTest.class);

    @Test
    public void asicsFromFilesTest() {
        List<DSSDocument> filesToBeSigned = new ArrayList<>();
        filesToBeSigned.add(new InMemoryDocument("Hello".getBytes(), "test.xml"));
        filesToBeSigned.add(new InMemoryDocument("Bye".getBytes(), "test2.xml"));

        ASiCWithXAdESSignatureParameters signatureParameters = new ASiCWithXAdESSignatureParameters();
        signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_S);

        ASiCWithXAdESDataToSignHelperBuilder builder = new ASiCWithXAdESDataToSignHelperBuilder();
        GetDataToSignASiCWithXAdESHelper getDataToSignHelper = builder.build(filesToBeSigned, signatureParameters);
        assertNotNull(getDataToSignHelper);

        List<DSSDocument> toBeSigned = getDataToSignHelper.getToBeSigned();
        assertEquals(1, toBeSigned.size());
        DSSDocument dssDocument = toBeSigned.get(0);
        assertEquals("package.zip", dssDocument.getName());

        byte[] byteArray = DSSUtils.toByteArray(dssDocument);
        LOG.info(new String(byteArray));
        String base64 = Utils.toBase64(byteArray);
        LOG.info(base64);

        String digest = dssDocument.getDigest(DigestAlgorithm.SHA256);

        LOG.info(digest);

        GetDataToSignASiCWithXAdESHelper getDataToSignHelperTwo = builder.build(filesToBeSigned, signatureParameters);
        assertNotNull(getDataToSignHelper);
        DSSDocument twice = getDataToSignHelperTwo.getToBeSigned().get(0);

        String digestTwice = twice.getDigest(DigestAlgorithm.SHA256);

        String base64twice = Utils.toBase64(DSSUtils.toByteArray(twice));
        LOG.info(base64twice);
        LOG.info(digestTwice);

        assertEquals(base64, base64twice);
        assertTrue(Utils.areStringsEqual(digest, digestTwice));
    }

}
