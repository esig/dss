package eu.europa.esig.dss.validation.process.qualification.certificate;

import eu.europa.esig.dss.enumerations.CertificateQualification;
import eu.europa.esig.dss.enumerations.CertificateQualifiedStatus;
import eu.europa.esig.dss.enumerations.CertificateType;
import eu.europa.esig.dss.enumerations.QSCDStatus;

/**
 * Determines the final qualification of a certificate giver two qualifications at issuance and best-signature-time
 * 
 */
public class FinalCertificateQualificationCalculator {
    
    /** Represents a qualification of a certificate at its issuance time (notBefore) */
    private final CertificateQualification certQualificationAtIssuanceTime;
    
    /** Represents a qualification of a certificate at the best-signature-time */
    private final CertificateQualification certQualificationAtBestSignatureTime;

    /**
     * Default constructor
     * 
     * @param certQualificationAtIssuanceTime {@link CertificateQualification} at its issuance time (notBefore)
     * @param certQualificationAtBestSignatureTime {@link CertificateQualification} at best-signature-time
     */
    public FinalCertificateQualificationCalculator(final CertificateQualification certQualificationAtIssuanceTime,
                                                   final CertificateQualification certQualificationAtBestSignatureTime) {
        this.certQualificationAtIssuanceTime = certQualificationAtIssuanceTime;
        this.certQualificationAtBestSignatureTime = certQualificationAtBestSignatureTime;
    }

    /**
     * This method returns the final qualification of the certificate, based on the two given times
     * 
     * @return {@link CertificateQualification}
     */
    public CertificateQualification getFinalQualification() {
        if (certQualificationAtIssuanceTime == certQualificationAtBestSignatureTime) {
            return certQualificationAtIssuanceTime;
        }
        if (CertificateQualification.NA.equals(certQualificationAtIssuanceTime) ||
                CertificateQualification.NA.equals(certQualificationAtBestSignatureTime)) {
            return CertificateQualification.NA;
        }
        CertificateQualifiedStatus qualStatus = getFinalCertQualStatus();
        CertificateType type = getFinalCertificateType();
        QSCDStatus qscd = getFinalQSCDStatus();
        return CertQualificationMatrix.getCertQualification(qualStatus, type, qscd);
    }

    private CertificateQualifiedStatus getFinalCertQualStatus() {
        return certQualificationAtIssuanceTime.isQc() && certQualificationAtBestSignatureTime.isQc() ?
                CertificateQualifiedStatus.QC : CertificateQualifiedStatus.NOT_QC;
    }

    private CertificateType getFinalCertificateType() {
        if (certQualificationAtIssuanceTime.getType() == certQualificationAtBestSignatureTime.getType()) {
            return certQualificationAtBestSignatureTime.getType();
        }
        return CertificateType.UNKNOWN;
    }

    private QSCDStatus getFinalQSCDStatus() {
        return certQualificationAtBestSignatureTime.isQscd() ? QSCDStatus.QSCD : QSCDStatus.NOT_QSCD;
    }
    
}
