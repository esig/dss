package eu.europa.esig.dss.cms.object.signature;

import eu.europa.esig.dss.cades.signature.CAdESSignatureTest;
import eu.europa.esig.dss.cades.validation.CAdESSignature;
import eu.europa.esig.dss.cms.CMS;
import eu.europa.esig.dss.cms.object.CMSSignedDataObject;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertThrows;

public class CAdESSignatureCMSObjectTest extends CAdESSignatureTest {

    @Test
    void initEmptyByteArray() {
        assertThrows(CMSException.class, () -> new CAdESSignature(null, null));
    }

    @Override
    protected CMS initEmptyCMS() throws CMSException {
        return new CMSSignedDataObject(new CMSSignedData(new byte[] {}));
    }

}
