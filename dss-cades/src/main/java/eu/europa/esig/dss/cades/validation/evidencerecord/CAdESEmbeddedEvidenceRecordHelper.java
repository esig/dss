package eu.europa.esig.dss.cades.validation.evidencerecord;

import eu.europa.esig.dss.cades.validation.CAdESAttribute;
import eu.europa.esig.dss.cades.validation.CAdESSignature;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.validation.SignatureAttribute;
import eu.europa.esig.dss.spi.validation.evidencerecord.AbstractEmbeddedEvidenceRecordHelper;
import eu.europa.esig.dss.spi.validation.evidencerecord.SignatureEvidenceRecordDigestBuilder;

/**
 * This class contains common methods for validation of a CAdES embedded evidence record
 *
 */
public class CAdESEmbeddedEvidenceRecordHelper extends AbstractEmbeddedEvidenceRecordHelper {

    /** Detached documents provided to the validation */
    private DSSDocument detachedDocument;

    /**
     * Default constructor
     *
     * @param signature {@link CAdESSignature}
     * @param evidenceRecordAttribute {@link CAdESAttribute}
     */
    public CAdESEmbeddedEvidenceRecordHelper(final CAdESSignature signature,
                                             final CAdESAttribute evidenceRecordAttribute) {
        super(signature, evidenceRecordAttribute);
    }

    /**
     * Sets a detached document for validation
     *
     * @param detachedDocument {@link DSSDocument}
     */
    public void setDetachedDocument(DSSDocument detachedDocument) {
        this.detachedDocument = detachedDocument;
    }

    @Override
    protected SignatureEvidenceRecordDigestBuilder getDigestBuilder(AdvancedSignature signature,
                                                                    SignatureAttribute evidenceRecordAttribute, DigestAlgorithm digestAlgorithm) {
        CAdESEvidenceRecordDigestBuilder digestBuilder = new CAdESEvidenceRecordDigestBuilder(signature, evidenceRecordAttribute, digestAlgorithm);
        digestBuilder.setDetachedContent(detachedDocument);
        return digestBuilder;
    }

    @Override
    protected void setDEREncoding(SignatureEvidenceRecordDigestBuilder digestBuilder, boolean derEncoded) {
        if (digestBuilder instanceof CAdESEvidenceRecordDigestBuilder) {
            CAdESEvidenceRecordDigestBuilder cadesEvidenceRecordDigestBuilder = (CAdESEvidenceRecordDigestBuilder) digestBuilder;
            cadesEvidenceRecordDigestBuilder.setDEREncoded(derEncoded);
        } else {
            throw new IllegalArgumentException("The digestBuilder shall be an instance of CAdESEvidenceRecordDigestBuilder!");
        }
    }

    @Override
    public boolean isEncodingSelectionSupported() {
        return true;
    }

}
