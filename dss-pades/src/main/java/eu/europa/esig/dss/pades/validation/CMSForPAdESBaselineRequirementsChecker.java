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
package eu.europa.esig.dss.pades.validation;

import eu.europa.esig.dss.cades.validation.CAdESBaselineRequirementsChecker;
import eu.europa.esig.dss.cades.validation.CAdESSignature;
import eu.europa.esig.dss.enumerations.SignatureForm;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class is used to verify conformance of a CMSSignedData to be incorporated to a PDF as a PAdES signature
 *
 */
public class CMSForPAdESBaselineRequirementsChecker extends CAdESBaselineRequirementsChecker {

    private static final Logger LOG = LoggerFactory.getLogger(CMSForPAdESBaselineRequirementsChecker.class);

    /**
     * Default constructor used to verify CMS of {@code CAdESSignature} on conformance to PAdES Baseline-B format
     *
     * @param signature {@link CAdESSignature} to be verified
     */
    public CMSForPAdESBaselineRequirementsChecker(CAdESSignature signature) {
        super(signature);
    }

    /**
     * This method verifies validity of a CMS signature for enveloping within a PDF signature of PAdES-BASELINE format
     *
     * @return TRUE if the CMS signature is conformant to PAdES-BASELINE format, FALSE otherwise
     */
    public boolean isValidForPAdESBaselineBProfile() {
        if (signature.getCmsSignedData().getSignerInfos().size() != 1) {
            LOG.warn("SignedData.signerInfos shall contain one and only one signerInfo for {}-BASELINE-B signature (cardinality == 1)!", getBaselineSignatureForm());
            return false;
        }
        return cmsBaselineBRequirements();
    }

    @Override
    protected SignatureForm getBaselineSignatureForm() {
        return SignatureForm.PAdES;
    }

}
