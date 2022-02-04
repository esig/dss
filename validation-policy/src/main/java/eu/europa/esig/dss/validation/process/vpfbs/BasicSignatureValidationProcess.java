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
package eu.europa.esig.dss.validation.process.vpfbs;

import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlProofOfExistence;
import eu.europa.esig.dss.detailedreport.jaxb.XmlTimestamp;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessBasicSignature;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessTimestamp;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.utils.Utils;

import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Signature validation process at validation time as per EN 319 102-1 ch. "5.3 Validation process for Basic Signatures"
 *
 */
public class BasicSignatureValidationProcess extends AbstractBasicValidationProcess<XmlValidationProcessBasicSignature> {

    /** List of timestamps within the signature */
    private final List<XmlTimestamp> xmlTimestamps;

    /**
     * Default constructor
     *
     * @param i18nProvider   {@link I18nProvider}
     * @param diagnosticData {@link DiagnosticData}
     * @param signatureWrapper {@link SignatureWrapper}
     * @param xmlTimestamps a collection of {@link XmlTimestamp} validations
     * @param bbbs           map of BasicBuildingBlocks
     */
    public BasicSignatureValidationProcess(I18nProvider i18nProvider, DiagnosticData diagnosticData, SignatureWrapper signatureWrapper,
                                           List<XmlTimestamp> xmlTimestamps, Map<String, XmlBasicBuildingBlocks> bbbs) {
        super(i18nProvider, new XmlValidationProcessBasicSignature(), diagnosticData, signatureWrapper, bbbs);
        this.xmlTimestamps = xmlTimestamps;
        result.setProofOfExistence(getCurrentTime(diagnosticData));
    }

    @Override
    protected MessageTag getTitle() {
        return MessageTag.VPBS;
    }

    private XmlProofOfExistence getCurrentTime(DiagnosticData diagnosticData) {
        XmlProofOfExistence proofOfExistence = new XmlProofOfExistence();
        proofOfExistence.setTime(diagnosticData.getValidationDate());
        return proofOfExistence;
    }

    @Override
    protected List<TimestampWrapper> getContentTimestamps() {
        SignatureWrapper signature = diagnosticData.getSignatureById(token.getId());
        if (signature != null) {
            return signature.getContentTimestamps();
        }
        return Collections.emptyList();
    }

    @Override
    protected XmlValidationProcessTimestamp getTimestampValidation(String timestampId) {
        for (XmlTimestamp xmlTimestamp : xmlTimestamps) {
            if (Utils.areStringsEqual(timestampId, xmlTimestamp.getId())) {
                return xmlTimestamp.getValidationProcessTimestamp();
            }
        }
        return null;
    }

}
