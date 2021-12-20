package eu.europa.esig.dss.asic.cades.timestamp;

import eu.europa.esig.dss.asic.cades.ASiCWithCAdESCommonParameters;
import eu.europa.esig.dss.asic.cades.signature.ASiCWithCAdESDataToSignHelperBuilder;
import eu.europa.esig.dss.asic.cades.signature.manifest.ASiCEWithCAdESManifestBuilder;
import eu.europa.esig.dss.asic.cades.signature.manifest.ASiCWithCAdESTimestampManifestBuilder;
import eu.europa.esig.dss.asic.cades.validation.ASiCWithCAdESUtils;
import eu.europa.esig.dss.asic.common.ASiCContent;

/**
 * This class is used to create a {@code GetDataToSignASiCWithCAdESHelper} for timestamp creation
 *
 */
public class ASiCWithCAdESTimestampDataToSignHelperBuilder extends ASiCWithCAdESDataToSignHelperBuilder {

    @Override
    protected ASiCEWithCAdESManifestBuilder getManifestBuilder(ASiCContent asicContent, ASiCWithCAdESCommonParameters parameters) {
        String uri = ASiCWithCAdESUtils.getTimestampFileName(asicContent.getTimestampDocuments());
        return new ASiCWithCAdESTimestampManifestBuilder(asicContent, parameters.getDigestAlgorithm(), uri);
    }

}
