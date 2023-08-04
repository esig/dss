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

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.signature.CAdESLevelBaselineB;
import eu.europa.esig.dss.cades.signature.CMSSignerInfoGeneratorBuilder;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSMessageDigest;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.cms.CMSAttributeTableGenerationException;
import org.bouncycastle.cms.CMSAttributeTableGenerator;
import org.bouncycastle.cms.SignerInfoGeneratorBuilder;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;

import java.util.Map;

/**
 * Builds a SignerInfoGenerator for a PAdES signature
 */
class PAdESSignerInfoGeneratorBuilder extends CMSSignerInfoGeneratorBuilder {

	private final DSSMessageDigest messageDigest;

	/**
	 * This is the default constructor for {@code CMSSignedDataGeneratorBuilder}.
	 *
	 * @param messageDigest {@link DSSMessageDigest} to be used for a signature computation
	 */
	public PAdESSignerInfoGeneratorBuilder(final DSSMessageDigest messageDigest) {
		this.messageDigest = messageDigest;
	}

	@Override
	protected SignerInfoGeneratorBuilder getSignerInfoGeneratorBuilder(CAdESSignatureParameters parameters, DSSDocument contentToSign) {
		final CAdESLevelBaselineB cadesLevelBaselineB = new CAdESLevelBaselineB(true);
		final PAdESLevelBaselineB padesProfileB = new PAdESLevelBaselineB();

		final DigestCalculatorProvider digestCalculatorProvider = new BcDigestCalculatorProvider();

		SignerInfoGeneratorBuilder signerInfoGeneratorBuilder = new SignerInfoGeneratorBuilder(digestCalculatorProvider);

		signerInfoGeneratorBuilder = signerInfoGeneratorBuilder.setSignedAttributeGenerator(new CMSAttributeTableGenerator() {
			@Override
			public AttributeTable getAttributes(Map params) throws CMSAttributeTableGenerationException {
				return padesProfileB.getSignedAttributes(params, cadesLevelBaselineB, parameters, messageDigest.getValue());
			}
		});

		signerInfoGeneratorBuilder = signerInfoGeneratorBuilder.setUnsignedAttributeGenerator(new CMSAttributeTableGenerator() {
			@Override
			public AttributeTable getAttributes(Map params) throws CMSAttributeTableGenerationException {
				return padesProfileB.getUnsignedAttributes();
			}
		});

		return signerInfoGeneratorBuilder;
	}

}
