package eu.europa.esig.dss.asic.cades.signature;

import eu.europa.esig.dss.asic.cades.ASiCWithCAdESCommonParameters;
import eu.europa.esig.dss.asic.cades.signature.manifest.ASiCEWithCAdESManifestBuilder;
import eu.europa.esig.dss.asic.cades.signature.manifest.ASiCWithCAdESSignatureManifestBuilder;
import eu.europa.esig.dss.asic.cades.validation.ASiCWithCAdESUtils;
import eu.europa.esig.dss.asic.common.ASiCContent;

/**
 * Builds a {@code GetDataToSignASiCWithCAdESHelper} for a signature creation
 *
 */
public class ASiCWithCAdESSignatureDataToSignHelperBuilder extends ASiCWithCAdESDataToSignHelperBuilder {

    @Override
    protected ASiCEWithCAdESManifestBuilder getManifestBuilder(ASiCContent asicContent, ASiCWithCAdESCommonParameters parameters) {
        String uri = ASiCWithCAdESUtils.getSignatureFileName(asicContent.getSignatureDocuments(),
                parameters.aSiC().getSignatureFileName());
        return new ASiCWithCAdESSignatureManifestBuilder(asicContent, parameters.getDigestAlgorithm(), uri);
    }

}
