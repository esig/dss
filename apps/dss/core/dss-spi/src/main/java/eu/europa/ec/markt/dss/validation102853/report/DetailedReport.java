/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2013 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2013 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */

package eu.europa.ec.markt.dss.validation102853.report;

import java.util.ArrayList;
import java.util.List;

import org.w3c.dom.Document;

import eu.europa.ec.markt.dss.validation102853.TimestampType;
import eu.europa.ec.markt.dss.validation102853.rules.Indication;
import eu.europa.ec.markt.dss.validation102853.rules.MessageTag;
import eu.europa.ec.markt.dss.validation102853.xml.XmlDom;

/**
 * This class represents the detailed report built during the validation process. It contains information on each executed constraint. It is composed among other of the
 * following building blocks:<br/>
 * - Identification of the Signer's Certificate (ISC)<br/>
 * - Validation Context Initialization (VCI)<br/>
 * - X.509 Certificate Validation (XCV)<br/>
 * - Cryptographic Verification (CV)<br/>
 * - Signature Acceptance Validation (SAV)<br/>
 * - Basic Validation Process<br/>
 * - Validation Process for Time-Stamps<br/>
 * - Validation Process for AdES-T<br/>
 * - Validation of LTV forms<br/>
 *
 * <p>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 */
public class DetailedReport extends XmlDom {

    public DetailedReport(final Document document) {

        super(document);
    }

    /**
     * Returns the number of the signatures into the signed document.
     *
     * @return
     */
    public long getSignaturesNumber() {

        final long signaturesNumber = getCountValue("count(/ValidationData/BasicBuildingBlocks/Signature)");
        return signaturesNumber;
    }

    /**
     * Returns the id of the signature. The signature is identified by its index: 1 for the first one.
     *
     * @param index
     * @return
     */
    public String getSignatureId(final int index) {

        final String signatureId = getValue("/ValidationData/BasicBuildingBlocks/Signature[%s]/@Id", index);
        return signatureId;
    }

    public List<String> getBBBSignatureId() {

        final List<String> signatureIdList = new ArrayList<String>();

        final List<XmlDom> signatures = getElements("/ValidationData/BasicBuildingBlocks/Signature");
        for (final XmlDom signature : signatures) {

            final String signatureId = signature.getAttribute("Id");
            signatureIdList.add(signatureId);
        }

        return signatureIdList;
    }

    public String getBBBIndication(final String signatureId) {

        final String indication = getValue("/ValidationData/BasicBuildingBlocks/Signature[@Id='%s']/Conclusion/Indication/text()", signatureId);
        return indication;
    }

    public String getBBBSubIndication(final String signatureId) {

        final String indication = getValue("/ValidationData/BasicBuildingBlocks/Signature[@Id='%s']/Conclusion/SubIndication/text()", signatureId);
        return indication;
    }

    public List<String> getTimestampSignatureId() {

        final List<String> signatureIdList = new ArrayList<String>();

        final List<XmlDom> signatures = getElements("/ValidationData/TimestampValidationData/Signature");
        for (final XmlDom signature : signatures) {

            final String signatureId = signature.getAttribute("Id");
            signatureIdList.add(signatureId);
        }

        return signatureIdList;
    }

    public List<String> getTimestampId(final String signatureId, final TimestampType timestampType) {

        final List<String> timestampIdList = new ArrayList<String>();

        final List<XmlDom> timestamps = getElements("/ValidationData/TimestampValidationData/Signature[@Id='%s']/Timestamp[@Type='%s']", signatureId, timestampType);
        for (final XmlDom timestamp : timestamps) {

            final String timestampId = timestamp.getAttribute("Id");
            timestampIdList.add(timestampId);
        }
        return timestampIdList;
    }

    public String getTimestampIndication(final String signatureId, final String timestampId) {

        final String indication = getValue("/ValidationData/TimestampValidationData/Signature[@Id='%s']/Timestamp[@Id='%s']/BasicBuildingBlocks/Conclusion/Indication/text()",
              signatureId, timestampId);
        return indication;
    }

    public String getTimestampSubIndication(final String signatureId, final String timestampId) {

        final String indication = getValue("/ValidationData/TimestampValidationData/Signature[@Id='%s']/Timestamp[@Id='%s']/BasicBuildingBlocks/Conclusion/SubIndication/text()",
              signatureId, timestampId);
        return indication;
    }

    public List<String> getLTVSignatureId() {

        final List<String> signatureIdList = new ArrayList<String>();

        final List<XmlDom> signatures = getElements("/ValidationData/LongTermValidationData/Signature");
        for (final XmlDom signature : signatures) {

            final String signatureId = signature.getAttribute("Id");
            signatureIdList.add(signatureId);
        }

        return signatureIdList;
    }

    public String getLTVIndication(final String signatureId) {

        final String indication = getValue("/ValidationData/LongTermValidationData/Signature[@Id='%s']/Conclusion/Indication/text()", signatureId);
        return indication;
    }

    public String getLTVSubIndication(final String signatureId) {

        final String indication = getValue("/ValidationData/LongTermValidationData/Signature[@Id='%s']/Conclusion/SubIndication/text()", signatureId);
        return indication;
    }

    public boolean areBasicBuildingBlocksValid() {

        final List<XmlDom> indications = getElements("/ValidationData/BasicBuildingBlocks/Signature/Conclusion/Indication");
        boolean valid = indications.size() > 0;
        for (final XmlDom indication : indications) {

            valid = valid && Indication.VALID.equals(indication.getText());
        }
        return valid;
    }

    public boolean areLTVSignaturesValid() {

        final List<XmlDom> indications = getElements("/ValidationData/LongTermValidationData/Signature/Conclusion/Indication");
        boolean valid = indications.size() > 0;
        for (final XmlDom indication : indications) {

            valid = valid && Indication.VALID.equals(indication.getText());
        }
        return valid;
    }

    public boolean areTimestampsValid() {

        final List<XmlDom> indications = getElements("/ValidationData/TimestampValidationData/Signature/Timestamp/BasicBuildingBlocks/Conclusion/Indication");
        boolean valid = indications.size() > 0;
        for (final XmlDom indicationDom : indications) {

            final String indication = indicationDom.getText();
            valid = valid && Indication.VALID.equals(indication);
        }
        return valid;
    }

    public Boolean areTimestampsValidOrNull() {

        final List<XmlDom> indications = getElements("/ValidationData/TimestampValidationData/Signature/Timestamp/BasicBuildingBlocks/Conclusion/Indication");
        if (indications.size() == 0) {
            return null;
        } else {
            Boolean valid = true;
            for (final XmlDom indicationDom : indications) {

                final String indication = indicationDom.getText();
                valid = valid && Indication.VALID.equals(indication);
            }
            return valid;
        }
    }

    public String getPolicyNotice(final String signatureId) {

        final String notice = getValue("/ValidationData/BasicBuildingBlocks/Signature[@Id='%s']/VCI/Constraint/Notice/text()", signatureId);
        return notice;
    }

    /**
     * This method returns the status of the constraint with the given tag.
     *
     * @param tag the tag of the constraint to find.
     * @return the status of the constraint
     */
    public String getConstraintStatus(final MessageTag tag) {

        final String status = getValue("//Name[@NameId='%s']/../Status/text()", tag.name());
        return status;
    }

	/**
	 * This method returns the conclusion indication related to the AdESTValidation of a given signature
	 * @param signatureId
	 * @return
	 */
	public String getAdESTValidationIndication(final String signatureId) {

		final String indication = getValue("/ValidationData/AdESTValidationData/Signature[@Id='%s']/Conclusion/Indication/text()", signatureId);
		return indication;
	}

	/**
	 * This method returns the conclusion subIndication related to the AdESTValidation of a given signature
	 * @param signatureId
	 * @return
	 */
	public String getAdESTValidationSubIndication(final String signatureId) {

		final String subIndication = getValue("/ValidationData/AdESTValidationData/Signature[@Id='%s']/Conclusion/SubIndication/text()", signatureId);
		return subIndication;
	}
}
