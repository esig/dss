/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.pades.signature;

import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.signature.SignatureRequirementsChecker;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.validation.status.SignatureStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class is used to verify signature creation or augmentation requirements for PAdES signatures
 *
 */
public class PAdESSignatureRequirementsChecker extends SignatureRequirementsChecker {

    private static final Logger LOG = LoggerFactory.getLogger(PAdESSignatureRequirementsChecker.class);

    /**
     * Default constructor
     *
     * @param certificateVerifier {@link CertificateVerifier}
     * @param signatureParameters {@link PAdESSignatureParameters}
     */
    public PAdESSignatureRequirementsChecker(CertificateVerifier certificateVerifier, PAdESSignatureParameters signatureParameters) {
        super(certificateVerifier, signatureParameters);
    }

    @Override
    protected void checkTLevelIsHighest(AdvancedSignature signature, SignatureStatus status) {
        if (signature.hasLTAProfile()) {
            status.addRelatedTokenAndErrorMessage(signature, "The signature is already extended with a higher level.");

        } else if (signature.hasLTProfile() && !signature.areAllSelfSignedCertificates()) {
            if (signature.hasTProfile()) {
                status.addRelatedTokenAndErrorMessage(signature, "The signature is already extended with a higher level.");
            }
            // NOTE: Otherwise allow extension, as it may be required to provide a best-signature-time
            // to ensure the best practice of fresh revocation data incorporation
            LOG.info("Signature contains a DSS dictionary, but no associated timestamp. " +
                    "Extension may lead to LTA-level.");
        }
    }

}
