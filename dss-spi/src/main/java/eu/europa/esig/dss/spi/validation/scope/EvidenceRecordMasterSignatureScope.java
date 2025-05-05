package eu.europa.esig.dss.spi.validation.scope;

import eu.europa.esig.dss.enumerations.SignatureScopeType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;

/**
 * Defines a master signature scope covered by an embedded evidence record
 * 
 */
public class EvidenceRecordMasterSignatureScope extends CounterSignatureScope {

    private static final long serialVersionUID = -7547927065332968662L;

    /**
     * Default constructor
     *
     * @param masterSignature {@link String}
     * @param originalDocument {@link DSSDocument}
     */
    public EvidenceRecordMasterSignatureScope(final AdvancedSignature masterSignature, final DSSDocument originalDocument) {
        super(masterSignature, originalDocument);
    }

    @Override
    public SignatureScopeType getType() {
        return SignatureScopeType.SIGNATURE;
    }

}
