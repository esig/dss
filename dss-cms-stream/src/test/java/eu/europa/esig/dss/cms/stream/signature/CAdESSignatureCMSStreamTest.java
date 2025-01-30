package eu.europa.esig.dss.cms.stream.signature;

import eu.europa.esig.dss.cades.signature.CAdESSignatureTest;
import eu.europa.esig.dss.cades.validation.CAdESSignature;
import eu.europa.esig.dss.cms.CMS;
import eu.europa.esig.dss.cms.stream.CMSSignedDataStream;
import org.bouncycastle.cms.CMSException;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertThrows;

public class CAdESSignatureCMSStreamTest extends CAdESSignatureTest {

    @Test
    void initEmptyByteArray() {
        assertThrows(CMSException.class, () -> new CAdESSignature(null, null));
    }

    @Override
    protected CMS initEmptyCMS() {
        return new CMSSignedDataStream();
    }

}
