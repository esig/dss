package eu.europa.esig.dss.xades.evidencerecord;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.validation.SignatureAttribute;
import eu.europa.esig.dss.spi.validation.evidencerecord.AbstractEmbeddedEvidenceRecordHelper;
import eu.europa.esig.dss.spi.validation.evidencerecord.SignatureEvidenceRecordDigestBuilder;
import eu.europa.esig.dss.xades.validation.XAdESAttribute;
import eu.europa.esig.dss.xades.validation.XAdESSignature;

import java.util.List;

/**
 * This class contains common methods for validation of a XAdES embedded evidence record
 *
 */
public class XAdESEmbeddedEvidenceRecordHelper extends AbstractEmbeddedEvidenceRecordHelper {

    /** List of detached documents provided to the validation */
    private List<DSSDocument> detachedContents;

    /**
     * Default constructor
     *
     * @param signature {@link XAdESSignature}
     * @param evidenceRecordAttribute {@link XAdESAttribute}
     */
    public XAdESEmbeddedEvidenceRecordHelper(final XAdESSignature signature,
                                             final XAdESAttribute evidenceRecordAttribute) {
        super(signature, evidenceRecordAttribute);
    }

    /**
     * Sets a list of documents used for validation of a detached signature
     *
     * @param detachedContents list of {@link DSSDocument}s
     */
    public void setDetachedContents(List<DSSDocument> detachedContents) {
        this.detachedContents = detachedContents;
    }

    @Override
    protected SignatureEvidenceRecordDigestBuilder getDigestBuilder(AdvancedSignature signature,
            SignatureAttribute evidenceRecordAttribute, DigestAlgorithm digestAlgorithm) {
        XAdESEvidenceRecordDigestBuilder digestBuilder = new XAdESEvidenceRecordDigestBuilder(signature, evidenceRecordAttribute, digestAlgorithm);
        digestBuilder.setDetachedContent(detachedContents);
        return digestBuilder;
    }

    @Override
    protected void setDEREncoding(SignatureEvidenceRecordDigestBuilder digestBuilder, boolean derEncoded) {
        throw new UnsupportedOperationException(
                "The #setEncoding method is not supported for a XAdES signature digest computation!");
    }

    @Override
    public boolean isEncodingSelectionSupported() {
        return false;
    }

}
