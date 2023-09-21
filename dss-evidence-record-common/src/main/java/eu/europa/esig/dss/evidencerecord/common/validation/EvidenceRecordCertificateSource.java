package eu.europa.esig.dss.evidencerecord.common.validation;

import eu.europa.esig.dss.enumerations.CertificateOrigin;
import eu.europa.esig.dss.enumerations.CertificateSourceType;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.TokenCertificateSource;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;


/**
 * Extracts and returns certificate tokens embedded within an Evidence Record structure
 *
 */
public class EvidenceRecordCertificateSource extends TokenCertificateSource {

    private static final long serialVersionUID = -6983984636774915526L;

    private static final Logger LOG = LoggerFactory.getLogger(EvidenceRecordCertificateSource.class);

    /**
     * List of {@code ArchiveTimeStampChainObject} representing a structure of an Evidence Record
     */
    private final List<? extends ArchiveTimeStampChainObject> archiveTimeStampSequence;

    /**
     * Default constructor
     *
     * @param archiveTimeStampSequence a list of {@link ArchiveTimeStampChainObject}s
     */
    public EvidenceRecordCertificateSource(final List<? extends ArchiveTimeStampChainObject> archiveTimeStampSequence) {
        this.archiveTimeStampSequence = archiveTimeStampSequence;
        extractCertificates();
    }

    /**
     * This method extracts certificates from the given xpath query
     */
    private void extractCertificates() {
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
                            if (CryptographicInformationType.CERT.equals(cryptographicInformation.getType())) {
                                byte[] derEncodedCert = cryptographicInformation.getContent();
                                try {
                                    final CertificateToken cert = DSSUtils.loadCertificate(derEncodedCert);
                                    addCertificate(cert, CertificateOrigin.EVIDENCE_RECORD);
                                } catch (Exception e) {
                                    LOG.warn("Unable to parse certificate '{}' : {}", Utils.toBase64(derEncodedCert), e.getMessage(), e);
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

    @Override
    public CertificateSourceType getCertificateSourceType() {
        return CertificateSourceType.EVIDENCE_RECORD;
    }

}
