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

package eu.europa.ec.markt.dss.signature.cades;

import java.util.ArrayList;
import java.util.Collection;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;

import eu.europa.ec.markt.dss.OID;
import eu.europa.ec.markt.dss.validation102853.CertificateVerifier;


public class CounterSignatureBuilder extends CMSSignedDataBuilder {

	private CMSSignedData cmsSignedData;
	private SignerId selector;

	protected CounterSignatureBuilder(final CertificateVerifier verifier) {
		super(verifier);
	}

	public void setCmsSignedData(CMSSignedData cmsSignedData) {
		this.cmsSignedData = cmsSignedData;
	}

	public void setSelector(SignerId selector) {
		this.selector = selector;
	}

	/**
	 * This method applies a countersignature to an existing signature
	 * @param signedData the countersignature
	 * @return the updated signature, in which the countersignature has been embedded
	 */
	public CMSSignedData signDocument(final CMSSignedData signedData) {

		final ASN1ObjectIdentifier csIdentifier = OID.id_countersignature;

		//Retrieve the SignerInformation from the countersigned signature
		final SignerInformationStore originalSignerInfos = cmsSignedData.getSignerInfos();
		//Retrieve the SignerInformation from the countersignature
		final SignerInformationStore signerInfos = signedData.getSignerInfos();

		//Add the countersignature
		SignerInformation updatedSI = cmsSignedData.getSignerInfos().get(selector).addCounterSigners(originalSignerInfos.get(selector), signerInfos);

		//Create updated SignerInformationStore
		Collection<SignerInformation> counterSignatureInformationCollection = new ArrayList<SignerInformation>();
		counterSignatureInformationCollection.add(updatedSI);
		SignerInformationStore signerInformationStore = new SignerInformationStore(counterSignatureInformationCollection);

		//Return new, updated signature
		return CMSSignedData.replaceSigners(cmsSignedData, signerInformationStore);
	}
}
