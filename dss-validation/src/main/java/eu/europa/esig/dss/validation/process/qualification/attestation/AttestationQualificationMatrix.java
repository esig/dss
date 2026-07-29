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
package eu.europa.esig.dss.validation.process.qualification.attestation;

import eu.europa.esig.dss.enumerations.AttestationQualification;
import eu.europa.esig.dss.enumerations.CertificateApprovalStatus;
import eu.europa.esig.dss.enumerations.CertificateApprovalStatusEnum;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureQualification;

/**
 * Builds an attestation qualification result based on the given parameters
 *
 */
public final class AttestationQualificationMatrix {

    /**
     * Empty constructor
     */
    private AttestationQualificationMatrix() {
        // empty
    }

    /** attestation passed validation process */
    private static final int PASSED_EAA = 0;

    /** attestation with an indeterminate result of validation process */
    private static final int INDETERMINATE_EAA = 1;

    /** attestation failed validation process */
    private static final int FAILED_EAA = 2;

    /** Qualified attestation */
    private static final int QEAA = 0;

    /** Public Sector Body attestation */
    private static final int PUBEAA = 1;

    /** Non-qualified attestation */
    private static final int EAA = 2;

    /** Unknown attestation */
    private static final int UNKNOWN_EAA = 3;

    /** Not attestation */
    private static final int NOT_EAA = 4;

    /** Qualified electronic signature or seal */
    private static final int QUAL_SIG_SEAL = 0;

    /** Indeterminate qualified electronic signature or seal */
    private static final int INDETERMINATE_QUAL_SIG_SEAL = 1;

    /** Non-qualified electronic signature or seal */
    private static final int NOT_QUAL_SIG_SEAL = 2;

    /** Not applicable validation revocation of electronic signature or seal */
    private static final int NA = 3;

    /** Certificate is a PID Provider */
    private static final int CERT_USAGE_PID = 0;

    /** Certificate is not a PID Provider */
    private static final int CERT_USAGE_OTHER = 1;

    /** Not applicable validation of a PID Provider */
    private static final int CERT_USAGE_NA = 2;

    /**
     * Array containing the relationship between qualification parameters and the final attestation qualification
     */
    private static final AttestationQualification[][][] QUALIFS = new AttestationQualification[3][5][4];

    /**
     * Array containing the relationship between qualification parameters and the final PID qualification
     */
    private static final AttestationQualification[][] PID_QUALIFS = new AttestationQualification[3][3];

    static {

        // Passed

        QUALIFS[PASSED_EAA][QEAA][QUAL_SIG_SEAL] = AttestationQualification.QEAA;
        QUALIFS[PASSED_EAA][QEAA][INDETERMINATE_QUAL_SIG_SEAL] = AttestationQualification.INDETERMINATE_QEAA;
        QUALIFS[PASSED_EAA][QEAA][NOT_QUAL_SIG_SEAL] = AttestationQualification.EAA;
        QUALIFS[PASSED_EAA][QEAA][NA] = AttestationQualification.NA;

        QUALIFS[PASSED_EAA][PUBEAA][QUAL_SIG_SEAL] = AttestationQualification.PUBEAA;
        QUALIFS[PASSED_EAA][PUBEAA][INDETERMINATE_QUAL_SIG_SEAL] = AttestationQualification.INDETERMINATE_PUBEAA;
        QUALIFS[PASSED_EAA][PUBEAA][NOT_QUAL_SIG_SEAL] = AttestationQualification.EAA;
        QUALIFS[PASSED_EAA][PUBEAA][NA] = AttestationQualification.NA;

        QUALIFS[PASSED_EAA][EAA][QUAL_SIG_SEAL] = AttestationQualification.EAA;
        QUALIFS[PASSED_EAA][EAA][INDETERMINATE_QUAL_SIG_SEAL] = AttestationQualification.INDETERMINATE_EAA;
        QUALIFS[PASSED_EAA][EAA][NOT_QUAL_SIG_SEAL] = AttestationQualification.EAA;
        QUALIFS[PASSED_EAA][EAA][NA] = AttestationQualification.NA;

        QUALIFS[PASSED_EAA][UNKNOWN_EAA][QUAL_SIG_SEAL] = AttestationQualification.UNKNOWN;
        QUALIFS[PASSED_EAA][UNKNOWN_EAA][INDETERMINATE_QUAL_SIG_SEAL] = AttestationQualification.INDETERMINATE_UNKNOWN;
        QUALIFS[PASSED_EAA][UNKNOWN_EAA][NOT_QUAL_SIG_SEAL] = AttestationQualification.UNKNOWN;
        QUALIFS[PASSED_EAA][UNKNOWN_EAA][NA] = AttestationQualification.NA;

        // Indeterminate EAA

        QUALIFS[INDETERMINATE_EAA][QEAA][QUAL_SIG_SEAL] = AttestationQualification.INDETERMINATE_QEAA;
        QUALIFS[INDETERMINATE_EAA][QEAA][INDETERMINATE_QUAL_SIG_SEAL] = AttestationQualification.INDETERMINATE_QEAA;
        QUALIFS[INDETERMINATE_EAA][QEAA][NOT_QUAL_SIG_SEAL] = AttestationQualification.INDETERMINATE_EAA;
        QUALIFS[INDETERMINATE_EAA][QEAA][NA] = AttestationQualification.NA;

        QUALIFS[INDETERMINATE_EAA][PUBEAA][QUAL_SIG_SEAL] = AttestationQualification.INDETERMINATE_PUBEAA;
        QUALIFS[INDETERMINATE_EAA][PUBEAA][INDETERMINATE_QUAL_SIG_SEAL] = AttestationQualification.INDETERMINATE_PUBEAA;
        QUALIFS[INDETERMINATE_EAA][PUBEAA][NOT_QUAL_SIG_SEAL] = AttestationQualification.INDETERMINATE_EAA;
        QUALIFS[INDETERMINATE_EAA][PUBEAA][NA] = AttestationQualification.NA;

        QUALIFS[INDETERMINATE_EAA][EAA][QUAL_SIG_SEAL] = AttestationQualification.INDETERMINATE_EAA;
        QUALIFS[INDETERMINATE_EAA][EAA][INDETERMINATE_QUAL_SIG_SEAL] = AttestationQualification.INDETERMINATE_EAA;
        QUALIFS[INDETERMINATE_EAA][EAA][NOT_QUAL_SIG_SEAL] = AttestationQualification.INDETERMINATE_EAA;
        QUALIFS[INDETERMINATE_EAA][EAA][NA] = AttestationQualification.NA;

        QUALIFS[INDETERMINATE_EAA][UNKNOWN_EAA][QUAL_SIG_SEAL] = AttestationQualification.INDETERMINATE_UNKNOWN;
        QUALIFS[INDETERMINATE_EAA][UNKNOWN_EAA][INDETERMINATE_QUAL_SIG_SEAL] = AttestationQualification.INDETERMINATE_UNKNOWN;
        QUALIFS[INDETERMINATE_EAA][UNKNOWN_EAA][NOT_QUAL_SIG_SEAL] = AttestationQualification.INDETERMINATE_UNKNOWN;
        QUALIFS[INDETERMINATE_EAA][UNKNOWN_EAA][NA] = AttestationQualification.NA;

        QUALIFS[INDETERMINATE_EAA][NOT_EAA][QUAL_SIG_SEAL] = AttestationQualification.NOT_EAA;
        QUALIFS[INDETERMINATE_EAA][NOT_EAA][INDETERMINATE_QUAL_SIG_SEAL] = AttestationQualification.NOT_EAA;
        QUALIFS[INDETERMINATE_EAA][NOT_EAA][NOT_QUAL_SIG_SEAL] = AttestationQualification.NOT_EAA;
        QUALIFS[INDETERMINATE_EAA][NOT_EAA][NA] = AttestationQualification.NA;

        // Not EAA

        QUALIFS[FAILED_EAA][QEAA][QUAL_SIG_SEAL] = AttestationQualification.NOT_EAA;
        QUALIFS[FAILED_EAA][QEAA][INDETERMINATE_QUAL_SIG_SEAL] = AttestationQualification.NOT_EAA;
        QUALIFS[FAILED_EAA][QEAA][NOT_QUAL_SIG_SEAL] = AttestationQualification.NOT_EAA;
        QUALIFS[FAILED_EAA][QEAA][NA] = AttestationQualification.NA;

        QUALIFS[FAILED_EAA][PUBEAA][QUAL_SIG_SEAL] = AttestationQualification.NOT_EAA;
        QUALIFS[FAILED_EAA][PUBEAA][INDETERMINATE_QUAL_SIG_SEAL] = AttestationQualification.NOT_EAA;
        QUALIFS[FAILED_EAA][PUBEAA][NOT_QUAL_SIG_SEAL] = AttestationQualification.NOT_EAA;
        QUALIFS[FAILED_EAA][PUBEAA][NA] = AttestationQualification.NA;

        QUALIFS[FAILED_EAA][EAA][QUAL_SIG_SEAL] = AttestationQualification.NOT_EAA;
        QUALIFS[FAILED_EAA][EAA][INDETERMINATE_QUAL_SIG_SEAL] = AttestationQualification.NOT_EAA;
        QUALIFS[FAILED_EAA][EAA][NOT_QUAL_SIG_SEAL] = AttestationQualification.NOT_EAA;
        QUALIFS[FAILED_EAA][EAA][NA] = AttestationQualification.NA;

        QUALIFS[FAILED_EAA][UNKNOWN_EAA][QUAL_SIG_SEAL] = AttestationQualification.NOT_EAA;
        QUALIFS[FAILED_EAA][UNKNOWN_EAA][INDETERMINATE_QUAL_SIG_SEAL] = AttestationQualification.NOT_EAA;
        QUALIFS[FAILED_EAA][UNKNOWN_EAA][NOT_QUAL_SIG_SEAL] = AttestationQualification.NOT_EAA;
        QUALIFS[FAILED_EAA][UNKNOWN_EAA][NA] = AttestationQualification.NA;

        QUALIFS[FAILED_EAA][NOT_EAA][QUAL_SIG_SEAL] = AttestationQualification.NOT_EAA;
        QUALIFS[FAILED_EAA][NOT_EAA][INDETERMINATE_QUAL_SIG_SEAL] = AttestationQualification.NOT_EAA;
        QUALIFS[FAILED_EAA][NOT_EAA][NOT_QUAL_SIG_SEAL] = AttestationQualification.NOT_EAA;
        QUALIFS[FAILED_EAA][NOT_EAA][NA] = AttestationQualification.NA;

        // PID

        PID_QUALIFS[PASSED_EAA][CERT_USAGE_PID] = AttestationQualification.PID;
        PID_QUALIFS[PASSED_EAA][CERT_USAGE_OTHER] = AttestationQualification.UNKNOWN;
        PID_QUALIFS[PASSED_EAA][CERT_USAGE_NA] = AttestationQualification.NA;

        PID_QUALIFS[INDETERMINATE_EAA][CERT_USAGE_PID] = AttestationQualification.INDETERMINATE_PID;
        PID_QUALIFS[INDETERMINATE_EAA][CERT_USAGE_OTHER] = AttestationQualification.INDETERMINATE_UNKNOWN;
        PID_QUALIFS[INDETERMINATE_EAA][CERT_USAGE_NA] = AttestationQualification.NA;

        PID_QUALIFS[FAILED_EAA][CERT_USAGE_PID] = AttestationQualification.NOT_EAA;
        PID_QUALIFS[FAILED_EAA][CERT_USAGE_OTHER] = AttestationQualification.NOT_EAA;
        PID_QUALIFS[FAILED_EAA][CERT_USAGE_NA] = AttestationQualification.NA;

    }

    /**
     * Gets attestation qualification based on the given parameters
     *
     * @param indication {@link Indication} representing the final result of validation process for attestation presentation
     * @param claimedQualification {@link AttestationQualification} claimed qualification extracted from the attestation signed payload
     * @param signatureQualification {@link SignatureQualification} of the signature used to create the attestation
     * @return {@link AttestationQualification}
     */
    public static AttestationQualification getAttestationQualification(Indication indication, AttestationQualification claimedQualification,
                                                               SignatureQualification signatureQualification) {
        return QUALIFS[getInt(indication)][getInt(claimedQualification)][getInt(signatureQualification)];
    }

    /**
     * Gets PID qualification based on the given parameters
     *
     * @param indication {@link Indication} representing the final result of validation process for attestation presentation
     * @param certificateApprovalStatus {@link CertificateApprovalStatus} determined certificate approval status
     * @return {@link AttestationQualification}
     */
    public static AttestationQualification getPIDQualification(Indication indication, CertificateApprovalStatus certificateApprovalStatus) {
        return PID_QUALIFS[getInt(indication)][getInt(certificateApprovalStatus)];
    }

    private static int getInt(Indication indication) {
        switch (indication) {
            case FAILED:
            case TOTAL_FAILED:
                return FAILED_EAA;
            case PASSED:
            case TOTAL_PASSED:
                return PASSED_EAA;
            case INDETERMINATE:
                return INDETERMINATE_EAA;
            default:
                throw new IllegalStateException("Unsupported indication " + indication);
        }
    }

    private static int getInt(AttestationQualification attestationQualification) {
        switch (attestationQualification) {
            case QEAA:
                return QEAA;
            case PUBEAA:
                return PUBEAA;
            case EAA:
                return EAA;
            case UNKNOWN:
                return UNKNOWN_EAA;
            case NOT_EAA:
                return NOT_EAA;
            default:
                throw new IllegalStateException("Unsupported attestation qualification " + attestationQualification);
        }
    }

    private static int getInt(SignatureQualification signatureQualification) {
        switch (signatureQualification) {
            case QESIG:
            case QESEAL:
                return QUAL_SIG_SEAL;
            case INDETERMINATE_QESIG:
            case INDETERMINATE_QESEAL:
                return INDETERMINATE_QUAL_SIG_SEAL;
            case NA:
                return NA;
            default:
                return NOT_QUAL_SIG_SEAL;
        }
    }

    private static int getInt(CertificateApprovalStatus certificateApprovalStatus) {
        if (CertificateApprovalStatusEnum.PID_PROVIDER == certificateApprovalStatus) {
            return CERT_USAGE_PID;
        } else if (CertificateApprovalStatusEnum.NA == certificateApprovalStatus) {
            return CERT_USAGE_NA;
        } else {
            return CERT_USAGE_OTHER;
        }
    }

}
