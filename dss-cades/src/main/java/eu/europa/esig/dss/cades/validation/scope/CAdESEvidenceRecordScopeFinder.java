package eu.europa.esig.dss.cades.validation.scope;

import eu.europa.esig.dss.cades.validation.CAdESSignature;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.identifier.TokenIdentifierProvider;
import eu.europa.esig.dss.model.scope.SignatureScope;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.validation.scope.EvidenceRecordMasterSignatureScope;
import eu.europa.esig.dss.spi.validation.scope.EvidenceRecordScopeFinder;
import eu.europa.esig.dss.spi.x509.evidencerecord.EvidenceRecord;

import java.util.List;

public class CAdESEvidenceRecordScopeFinder extends EvidenceRecordScopeFinder {

    /** Signature to cover */
    private final AdvancedSignature signature;

    /**
     * Default constructor
     *
     * @param evidenceRecord {@link EvidenceRecord}
     * @param signature {@link AdvancedSignature}
     */
    public CAdESEvidenceRecordScopeFinder(final EvidenceRecord evidenceRecord, final AdvancedSignature signature) {
        super(evidenceRecord);
        this.signature = signature;
    }

    @Override
    public List<SignatureScope> findEvidenceRecordScope() {
        List<SignatureScope> evidenceRecordScopes = super.findEvidenceRecordScope();
        if (isSignatureEmbeddedAndValid(evidenceRecord) && isSignatureCovered(evidenceRecord, signature)) {
            evidenceRecordScopes.add(new EvidenceRecordCAdESSignatureScope(signature, getCAdESSignatureDocument(signature)));
        }
        return evidenceRecordScopes;
    }

    private boolean isSignatureCovered(EvidenceRecord evidenceRecord, AdvancedSignature signature) {
        CAdESSignature masterSignature = (CAdESSignature) evidenceRecord.getMasterSignature();
        CAdESSignature cadesSignature = (CAdESSignature) signature;
        return masterSignature.getCMS() == cadesSignature.getCMS();
    }

    private DSSDocument getCAdESSignatureDocument(AdvancedSignature signature) {
        // TODO : improve ?
        CAdESSignature cadesSignature = (CAdESSignature) signature;
        byte[] derEncoded = DSSASN1Utils.getDEREncoded(cadesSignature.getSignerInformation().toASN1Structure());
        return createInMemoryDocument(derEncoded);
    }

    /**
     * This class is used for an evidence record scope definition, covering same CMS signature
     */
    private static class EvidenceRecordCAdESSignatureScope extends EvidenceRecordMasterSignatureScope {

        private static final long serialVersionUID = -1583386221534165955L;

        /**
         * Default constructor
         *
         * @param masterSignature {@link String}
         * @param originalDocument {@link DSSDocument}
         */
        public EvidenceRecordCAdESSignatureScope(final AdvancedSignature masterSignature,
                                                 final DSSDocument originalDocument) {
            super(masterSignature, originalDocument);
        }

        @Override
        public String getDescription(TokenIdentifierProvider tokenIdentifierProvider) {
            return String.format("Signature with Id : %s", tokenIdentifierProvider.getIdAsString(masterSignature));
        }

    }

}
