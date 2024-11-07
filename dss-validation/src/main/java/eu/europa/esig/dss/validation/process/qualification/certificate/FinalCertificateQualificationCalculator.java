/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
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
