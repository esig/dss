package eu.europa.esig.dss.asic.cades.signature;

import eu.europa.esig.dss.asic.cades.ASiCWithCAdESFilenameFactory;
import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.signature.AbstractASiCDataToSignHelperBuilder;
import eu.europa.esig.dss.utils.Utils;

public abstract class AbstractASiCWithCAdESDataToSignHelperBuilder extends AbstractASiCDataToSignHelperBuilder {

    /**
     * Defines rules for filename creation for new manifest files.
     */
    protected final ASiCWithCAdESFilenameFactory asicFilenameFactory;

    /**
     * Default constructor
     *
     * @param asicFilenameFactory {@link ASiCWithCAdESFilenameFactory}
     */
    protected AbstractASiCWithCAdESDataToSignHelperBuilder(final ASiCWithCAdESFilenameFactory asicFilenameFactory) {
        this.asicFilenameFactory = asicFilenameFactory;
    }

    /**
     * Gets whether the ASiC represents an existing archive
     *
     * @param asicContent {@link ASiCContent}
     * @return TRUE if the ASiCContent is an existing ASiC archive, FALSE otherwise
     */
    protected boolean isASiCArchive(ASiCContent asicContent) {
        return Utils.isCollectionNotEmpty(asicContent.getSignatureDocuments())
                || Utils.isCollectionNotEmpty(asicContent.getTimestampDocuments())
                || Utils.isCollectionNotEmpty(asicContent.getEvidenceRecordDocuments());
    }

    @Override
    protected String getDataPackageName(ASiCContent asicContent) {
        return asicFilenameFactory.getDataPackageFilename(asicContent);
    }

}
