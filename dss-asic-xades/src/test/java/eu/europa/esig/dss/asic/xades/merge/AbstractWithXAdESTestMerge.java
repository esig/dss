package eu.europa.esig.dss.asic.xades.merge;

import eu.europa.esig.dss.asic.common.merge.AbstractASiCTestMerge;
import eu.europa.esig.dss.asic.xades.ASiCWithXAdESSignatureParameters;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public abstract class AbstractWithXAdESTestMerge extends
        AbstractASiCTestMerge<ASiCWithXAdESSignatureParameters, XAdESTimestampParameters> {

    @Override
    protected void checkContainerInfo(DiagnosticData diagnosticData) {
        assertNotNull(diagnosticData.getContainerInfo());
        assertNotNull(diagnosticData.getContainerType());
        assertNotNull(diagnosticData.getMimetypeFileContent());
        assertTrue(Utils.isCollectionNotEmpty(diagnosticData.getContainerInfo().getContentFiles()));

        assertEquals(getFirstSignatureParameters().aSiC().getContainerType(), diagnosticData.getContainerType());
    }

}
