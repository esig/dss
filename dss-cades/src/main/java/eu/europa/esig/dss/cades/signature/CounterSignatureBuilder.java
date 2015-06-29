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
package eu.europa.esig.dss.cades.signature;

import java.util.ArrayList;
import java.util.Collection;

import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;

import eu.europa.esig.dss.validation.CertificateVerifier;


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
