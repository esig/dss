package eu.europa.esig.dss.evidencerecord.common.validation;

import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.spi.DSSRevocationUtils;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OfflineOCSPSource;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPResponseBinary;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

/**
 * Extracts and returns OCSP tokens embedded within an Evidence Record structure
 *
 */
public class EvidenceRecordOCSPSource extends OfflineOCSPSource {

    private static final long serialVersionUID = -8846746778038286512L;

    private static final Logger LOG = LoggerFactory.getLogger(EvidenceRecordOCSPSource.class);

    /**
     * List of {@code ArchiveTimeStampChainObject} representing a structure of an Evidence Record
     */
    private final List<? extends ArchiveTimeStampChainObject> archiveTimeStampSequence;

    /**
     * Default constructor
     *
     * @param archiveTimeStampSequence a list of {@link ArchiveTimeStampChainObject}s
     */
    public EvidenceRecordOCSPSource(final List<? extends ArchiveTimeStampChainObject> archiveTimeStampSequence) {
        this.archiveTimeStampSequence = archiveTimeStampSequence;
        extractOCSPs();
    }

    private void extractOCSPs() {
        if (Utils.isCollectionEmpty(archiveTimeStampSequence)) {
            return;
        }
        for (ArchiveTimeStampChainObject archiveTimeStampChainObject : archiveTimeStampSequence) {
            List<? extends ArchiveTimeStampObject> archiveTimeStamps = archiveTimeStampChainObject.getArchiveTimeStamps();
            if (Utils.isCollectionNotEmpty(archiveTimeStamps)) {
                for (ArchiveTimeStampObject archiveTimeStampObject : archiveTimeStamps) {
                    List<CryptographicInformation> cryptographicInformationList = archiveTimeStampObject.getCryptographicInformationList();
                    if (Utils.isCollectionNotEmpty(cryptographicInformationList)) {
                        for (CryptographicInformation cryptographicInformation : cryptographicInformationList) {
                            if (CryptographicInformationType.OCSP.equals(cryptographicInformation.getType())) {
                                byte[] derEncoded = cryptographicInformation.getContent();
                                try {
                                    OCSPResponseBinary ocspResponseBinary = OCSPResponseBinary.build(DSSRevocationUtils.loadOCSPFromBinaries(derEncoded));
                                    addBinary(ocspResponseBinary, RevocationOrigin.EVIDENCE_RECORD);
                                } catch (Exception e) {
                                    LOG.warn("Unable to parse OCSP '{}' : {}", Utils.toBase64(derEncoded), e.getMessage(), e);
                                }
                            }
                        }
                    }
                }
            }
        }
        if (LOG.isInfoEnabled()) {
            LOG.info("+EvidenceRecordCertificateSource");
        }
    }

}
