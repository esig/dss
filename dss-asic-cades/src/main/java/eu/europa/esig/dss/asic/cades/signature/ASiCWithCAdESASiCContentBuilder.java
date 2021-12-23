package eu.europa.esig.dss.asic.cades.signature;

import eu.europa.esig.dss.asic.cades.ASiCWithCAdESContainerExtractor;
import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.asic.common.AbstractASiCContainerExtractor;
import eu.europa.esig.dss.asic.common.ZipUtils;
import eu.europa.esig.dss.asic.common.signature.AbstractASiCContentBuilder;
import eu.europa.esig.dss.model.DSSDocument;

import java.util.List;

/**
 * Builds {@code ASiCContent} for an ASiC with CAdES container
 *
 */
public class ASiCWithCAdESASiCContentBuilder extends AbstractASiCContentBuilder {

    @Override
    protected boolean isAcceptableContainerFormat(DSSDocument archiveDocument) {
        List<String> filenames = ZipUtils.getInstance().extractEntryNames(archiveDocument);
        return ASiCUtils.isAsicFileContent(filenames);
    }

    @Override
    protected AbstractASiCContainerExtractor getContainerExtractor(DSSDocument archiveDocument) {
        return new ASiCWithCAdESContainerExtractor(archiveDocument);
    }

}
