package eu.europa.esig.dss.tsl.job.mra;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;

public class MRAWithCustomCertificateContentContextTest extends MRALOTLTest {

    @Override
    protected DSSDocument getOriginalLOTL() {
        return new FileDocument("src/test/resources/mra-zz-lotl-custom-equivalence-context.xml");
    }

}
