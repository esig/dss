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
package eu.europa.esig.dss.validation.process.bbb.fc.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlFC;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlManifestFile;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.SignatureForm;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.policy.LevelRule;
import eu.europa.esig.dss.utils.Utils;

/**
 * Verifies conformance of a related to a signature manifest filename
 *
 */
public class SignatureManifestFilenameAdherenceCheck extends FilenameAdherenceCheck<SignatureWrapper> {

    /**
     * Default constructor
     *
     * @param i18nProvider   {@link I18nProvider}
     * @param result         {@link XmlFC}
     * @param diagnosticData {@link DiagnosticData}
     * @param token          {@link SignatureWrapper}
     * @param constraint     {@link LevelRule}
     */
    public SignatureManifestFilenameAdherenceCheck(I18nProvider i18nProvider, XmlFC result, DiagnosticData diagnosticData,
                                           SignatureWrapper token, LevelRule constraint) {
        super(i18nProvider, result, diagnosticData, token, constraint);
    }

    @Override
    protected boolean process() {
        if (ASiCContainerType.ASiC_S == diagnosticData.getContainerType()) {
            /*
             * 4.3.3.2 Contents of the container
             *
             * The ASiC-S container:
             * 5) The META-INF folder may contain the following additional files:
             * c) Other application specific information.
             */
            return true; // can be of any format ?
        }
        XmlManifestFile manifestFile = diagnosticData.getManifestFileForFilename(token.getFilename());
        if (manifestFile == null) {
            // optional for XAdES, required for CAdES
            return SignatureForm.XAdES == token.getSignatureFormat().getSignatureForm();
        }

        String manifestFilename = manifestFile.getFilename();
        if (Utils.isStringEmpty(manifestFilename)) {
            return false;
        }
        switch (token.getSignatureFormat().getSignatureForm()) {
            case XAdES:
                return ASICE_METAINF_MANIFEST.equals(manifestFilename);
            case CAdES:
                return isASiCManifest(manifestFilename);
            default:
                throw new UnsupportedOperationException(String.format("Only XAdES and CAdES ASiC container types are supported! " +
                        "Found : %s", token.getSignatureFormat().getSignatureForm()));
        }
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.BBB_FC_IMFCS;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.BBB_FC_IMFCS_ANS;
    }

}