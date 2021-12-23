package eu.europa.esig.dss.asic.xades.signature;

import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.asic.common.AbstractASiCContainerExtractor;
import eu.europa.esig.dss.asic.common.ZipUtils;
import eu.europa.esig.dss.asic.common.signature.AbstractASiCContentBuilder;
import eu.europa.esig.dss.asic.xades.ASiCWithXAdESContainerExtractor;
import eu.europa.esig.dss.model.DSSDocument;

import java.util.List;

/**
 * Builds {@code ASiCContent} for an ASiC with CAdES container
 *
 */
public class ASiCWithXAdESASiCContentBuilder extends AbstractASiCContentBuilder {

    @Override
    protected boolean isAcceptableContainerFormat(DSSDocument archiveDocument) {
        List<String> filenames = ZipUtils.getInstance().extractEntryNames(archiveDocument);
        return ASiCUtils.isAsicFileContent(filenames) ||
                (ASiCUtils.areFilesContainMimetype(filenames) && ASiCUtils.isContainerOpenDocument(archiveDocument));
    }

    @Override
    protected AbstractASiCContainerExtractor getContainerExtractor(DSSDocument archiveDocument) {
        return new ASiCWithXAdESContainerExtractor(archiveDocument);
    }

}
