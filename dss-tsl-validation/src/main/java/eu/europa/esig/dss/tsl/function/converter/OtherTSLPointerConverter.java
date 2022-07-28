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
package eu.europa.esig.dss.tsl.function.converter;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.tsl.MRA;
import eu.europa.esig.dss.spi.tsl.OtherTSLPointer;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.trustedlist.jaxb.mra.MutualRecognitionAgreementInformationType;
import eu.europa.esig.trustedlist.jaxb.tsl.AdditionalInformationType;
import eu.europa.esig.trustedlist.jaxb.tsl.AnyType;
import eu.europa.esig.trustedlist.jaxb.tsl.DigitalIdentityListType;
import eu.europa.esig.trustedlist.jaxb.tsl.OtherTSLPointerType;
import eu.europa.esig.trustedlist.jaxb.tsl.ServiceDigitalIdentityListType;

import javax.xml.bind.JAXBElement;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.function.Function;

/**
 * The class is used to convert {@code OtherTSLPointerType} to {@code OtherTSLPointer}
 *
 */
public class OtherTSLPointerConverter implements Function<OtherTSLPointerType, OtherTSLPointer> {

	/** Defines whether MRA shall be extracted */
	private boolean mraSupport;

	/**
	 * Default constructor
	 *
	 * @param mraSupport defines whether MRA shall be extracted if present
	 */
	public OtherTSLPointerConverter(boolean mraSupport) {
		this.mraSupport = mraSupport;
	}

	@Override
	public OtherTSLPointer apply(OtherTSLPointerType original) {
		return new OtherTSLPointer(original.getTSLLocation(),
				Collections.unmodifiableList(getCertificates(original.getServiceDigitalIdentities())),
				getMRA(original.getAdditionalInformation()));
	}

	@SuppressWarnings("rawtypes")
	private MRA getMRA(AdditionalInformationType additionalInformation) {
		if (mraSupport && additionalInformation != null
				&& Utils.isCollectionNotEmpty(additionalInformation.getTextualInformationOrOtherInformation())) {
			for (Serializable serializableObj : additionalInformation.getTextualInformationOrOtherInformation()) {
				if (serializableObj instanceof AnyType) {
					AnyType anytype = (AnyType) serializableObj;
					List<Object> content = anytype.getContent();
					for (Object objectValue : content) {
						if (objectValue instanceof JAXBElement) {
							JAXBElement jaxbElement = (JAXBElement) objectValue;
							if (jaxbElement.getValue() instanceof MutualRecognitionAgreementInformationType) {
								MutualRecognitionAgreementInformationType jaxbMRA =
										(MutualRecognitionAgreementInformationType) jaxbElement.getValue();
								MRAConverter converter = new MRAConverter();
								return converter.apply(jaxbMRA);
							}
						}
					}
				}
			}
		}
		return null;
	}

	private List<CertificateToken> getCertificates(ServiceDigitalIdentityListType serviceDigitalIdentities) {
		List<CertificateToken> certificates = new ArrayList<>();
		if (serviceDigitalIdentities != null
				&& Utils.isCollectionNotEmpty(serviceDigitalIdentities.getServiceDigitalIdentity())) {
			DigitalIdentityListTypeConverter converter = new DigitalIdentityListTypeConverter();
			for (DigitalIdentityListType digitalIdentityList : serviceDigitalIdentities.getServiceDigitalIdentity()) {
				certificates.addAll(converter.apply(digitalIdentityList));
			}
		}
		return certificates;
	}

}
