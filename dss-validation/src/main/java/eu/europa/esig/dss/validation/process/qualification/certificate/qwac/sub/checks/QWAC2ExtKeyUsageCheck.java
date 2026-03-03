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
package eu.europa.esig.dss.validation.process.qualification.certificate.qwac.sub.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationQWACProcess;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOID;
import eu.europa.esig.dss.enumerations.ExtendedKeyUsage;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.policy.LevelRule;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.ChainItem;

import java.util.List;

/**
 * Verifies conformance of the "extended-key-usage" certificate extension for the 2-QWAC profile
 *
 */
public class QWAC2ExtKeyUsageCheck extends ChainItem<XmlValidationQWACProcess> {

    /** Certificate to be validated */
    private final CertificateWrapper certificate;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlValidationQWACProcess}
     * @param certificate {@link CertificateWrapper}
     * @param constraint {@link LevelRule}
     */
    public QWAC2ExtKeyUsageCheck(final I18nProvider i18nProvider, final XmlValidationQWACProcess result,
                               final CertificateWrapper certificate,final LevelRule constraint) {
        super(i18nProvider, result, constraint);
        this.certificate = certificate;
    }

    @Override
    protected boolean process() {
        List<XmlOID> extendedKeyUsages = certificate.getExtendedKeyUsages();
        return Utils.collectionSize(extendedKeyUsages) == 1 &&
                ExtendedKeyUsage.TSL_BINDING.getOid().equals(extendedKeyUsages.get(0).getValue());
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.QWAC2_EXT_KEY_USAGE;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.QWAC2_EXT_KEY_USAGE_ANS;
    }

    @Override
    protected Indication getFailedIndicationForConclusion() {
        return Indication.FAILED;
    }

    @Override
    protected SubIndication getFailedSubIndicationForConclusion() {
        return null;
    }

}
