package eu.europa.esig.dss.asic.cades.signature.manifest;

import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.MimeType;

/**
 * This class is used to create a Manifest file for a signature creation
 *
 */
public class ASiCWithCAdESSignatureManifestBuilder extends ASiCEWithCAdESManifestBuilder {

    /**
     * The default constructor
     *
     * @param asicContent     {@link ASiCContent} representing container's document structure
     * @param digestAlgorithm {@link DigestAlgorithm} to use for reference digest computation
     * @param documentUri     {@link String} filename of the document associated with the manifest
     */
    public ASiCWithCAdESSignatureManifestBuilder(ASiCContent asicContent, DigestAlgorithm digestAlgorithm, String documentUri) {
        super(asicContent, digestAlgorithm, documentUri);
    }

    @Override
    protected MimeType getSigReferenceMimeType() {
        return MimeType.PKCS7;
    }

}
