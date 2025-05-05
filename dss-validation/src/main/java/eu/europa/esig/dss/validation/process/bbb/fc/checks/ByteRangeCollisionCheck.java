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
import eu.europa.esig.dss.diagnostic.AbstractSignatureWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.policy.LevelRule;
import eu.europa.esig.dss.validation.process.ChainItem;

import java.math.BigInteger;
import java.util.List;

/**
 * Checks if the current signature /ByteRange does not collide with other signature byte ranges
 *
 */
public class ByteRangeCollisionCheck extends ChainItem<XmlFC> {

    /** The signature token to be checked */
    private final AbstractSignatureWrapper currentSignature;

    /** The diagnostic data */
    private final DiagnosticData diagnosticData;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlFC}
     * @param signatureWrapper {@link AbstractSignatureWrapper}
     * @param diagnosticData {@link DiagnosticData}
     * @param constraint {@link LevelRule}
     */
    public ByteRangeCollisionCheck(I18nProvider i18nProvider, XmlFC result, AbstractSignatureWrapper signatureWrapper,
                                   DiagnosticData diagnosticData, LevelRule constraint) {
        super(i18nProvider, result, constraint);
        this.currentSignature = signatureWrapper;
        this.diagnosticData = diagnosticData;
    }

    @Override
    protected boolean process() {
        for (SignatureWrapper signature : diagnosticData.getSignatures()) {
            if (!currentSignature.getId().equals(signature.getId()) && collide(currentSignature, signature)) {
                return false;
            }
        }
        for (TimestampWrapper timestamp : diagnosticData.getTimestampList()) {
            if (!currentSignature.getId().equals(timestamp.getId()) && collide(currentSignature, timestamp)) {
                return false;
            }
        }
        return true;
    }

    private boolean collide(AbstractSignatureWrapper signatureWrapperOne, AbstractSignatureWrapper signatureWrapperTwo) {
        return signatureWrapperOne.getPDFRevision() != null && signatureWrapperTwo.getPDFRevision() != null &&
                (collide(signatureWrapperOne.getPDFRevision().getSignatureByteRange(), signatureWrapperTwo.getPDFRevision().getSignatureByteRange()) ||
                collide(signatureWrapperTwo.getPDFRevision().getSignatureByteRange(), signatureWrapperOne.getPDFRevision().getSignatureByteRange()));
    }

    private boolean collide(List<BigInteger> byteRangeOne, List<BigInteger> byteRangeTwo) {
        if (byteRangeOne.size() != 4 || byteRangeTwo.size() != 4) {
            throw new IllegalStateException("Signature ByteRange shall have 4 integers!");
        }
        return getFirstByteRangePartLength(byteRangeOne) < getFirstByteRangePartLength(byteRangeTwo) !=
                getFirstByteRangePartLength(byteRangeOne) < getSecondByteRangePartLength(byteRangeTwo);
    }

    private int getFirstByteRangePartLength(List<BigInteger> byteRange) {
        return byteRange.get(0).intValue() + byteRange.get(1).intValue();
    }

    private int getSecondByteRangePartLength(List<BigInteger> byteRange) {
        return byteRange.get(2).intValue() + byteRange.get(3).intValue();
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.BBB_FC_DBTOOST;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.BBB_FC_DBTOOST_ANS;
    }

    @Override
    protected Indication getFailedIndicationForConclusion() {
        return Indication.FAILED;
    }

    @Override
    protected SubIndication getFailedSubIndicationForConclusion() {
        return SubIndication.FORMAT_FAILURE;
    }

}
