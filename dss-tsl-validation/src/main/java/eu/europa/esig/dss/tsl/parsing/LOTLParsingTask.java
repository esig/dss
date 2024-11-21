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
package eu.europa.esig.dss.tsl.parsing;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.tsl.function.LOTLSigningCertificatesAnnouncementSchemeInformationURI;
import eu.europa.esig.dss.tsl.function.PivotSchemeInformationURI;
import eu.europa.esig.dss.tsl.function.converter.OtherTSLPointerConverter;
import eu.europa.esig.dss.tsl.source.LOTLSource;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.trustedlist.TrustedListFacade;
import eu.europa.esig.trustedlist.jaxb.tsl.NonEmptyMultiLangURIListType;
import eu.europa.esig.trustedlist.jaxb.tsl.NonEmptyMultiLangURIType;
import eu.europa.esig.trustedlist.jaxb.tsl.OtherTSLPointerType;
import eu.europa.esig.trustedlist.jaxb.tsl.OtherTSLPointersType;
import eu.europa.esig.trustedlist.jaxb.tsl.TSLSchemeInformationType;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;
import eu.europa.esig.trustedlist.mra.MRAFacade;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * Parses a LOTL and returns {@code LOTLParsingResult}
 */
public class LOTLParsingTask extends AbstractParsingTask<LOTLParsingResult> {

	private static final Logger LOG = LoggerFactory.getLogger(LOTLParsingTask.class);

	/** The LOTLSource to parse */
	private final LOTLSource lotlSource;

	/**
	 * The default constructor
	 *
	 * @param document {@link DSSDocument} LOTL document to parse
	 * @param lotlSource {@link LOTLSource}
	 */
	public LOTLParsingTask(DSSDocument document, LOTLSource lotlSource) {
		super(document);
		Objects.requireNonNull(lotlSource, "The LOTLSource is null");
		this.lotlSource = lotlSource;
	}

	@Override
	public LOTLParsingResult get() {
		LOTLParsingResult result = new LOTLParsingResult();
		TrustStatusListType jaxbObject = getJAXBObject();

		parseSchemeInformation(result, jaxbObject.getSchemeInformation());
		verifyTLVersionConformity(result, result.getVersion());

		return result;
	}

	private void parseSchemeInformation(LOTLParsingResult result, TSLSchemeInformationType schemeInformation) {
		commonParseSchemeInformation(result, schemeInformation);
		extractOtherTSLPointers(result, schemeInformation);
		extractSchemeInformationURI(result, schemeInformation);
	}

	private void extractOtherTSLPointers(LOTLParsingResult result, TSLSchemeInformationType schemeInformation) {
		OtherTSLPointersType otherTSLPointersType = schemeInformation.getPointersToOtherTSL();
		if (otherTSLPointersType != null && Utils.isCollectionNotEmpty(otherTSLPointersType.getOtherTSLPointer())) {
			List<OtherTSLPointerType> otherTSLPointers = otherTSLPointersType.getOtherTSLPointer();
			OtherTSLPointerConverter converter = new OtherTSLPointerConverter(lotlSource.isMraSupport());
			result.setLotlPointers(otherTSLPointers.stream().filter(lotlSource.getLotlPredicate()).map(converter).collect(Collectors.toList()));
			result.setTlPointers(otherTSLPointers.stream().filter(lotlSource.getTlPredicate()).map(converter).collect(Collectors.toList()));
		}
	}

	private void extractSchemeInformationURI(LOTLParsingResult result, TSLSchemeInformationType schemeInformation) {
		NonEmptyMultiLangURIListType schemeInformationURI = schemeInformation.getSchemeInformationURI();
		if (schemeInformationURI != null) {
			extractSigningCertificatesAnnouncementURL(result, schemeInformationURI);
			extractPivotURLs(result, schemeInformationURI);
		}
	}

	private void extractSigningCertificatesAnnouncementURL(LOTLParsingResult result, NonEmptyMultiLangURIListType schemeInformationURI) {
		LOTLSigningCertificatesAnnouncementSchemeInformationURI signingCertificatesAnnouncementPredicate = lotlSource.getSigningCertificatesAnnouncementPredicate();
		if (signingCertificatesAnnouncementPredicate != null) {
			final List<String> uris = schemeInformationURI.getURI().stream().filter(signingCertificatesAnnouncementPredicate)
					.map(NonEmptyMultiLangURIType::getValue).collect(Collectors.toList());
			if (Utils.isCollectionNotEmpty(uris)) {
				String newUri = uris.get(0);
				if (!newUri.equals(signingCertificatesAnnouncementPredicate.getUri())) {
					LOG.warn("LOTLSigningCertificatesAnnouncement URI change detected. New URI : {}", newUri);
				}
				result.setSigningCertificateAnnouncementURL(newUri);
			}
		}
	}

	private void extractPivotURLs(LOTLParsingResult result, NonEmptyMultiLangURIListType schemeInformationURI) {
		if (lotlSource.isPivotSupport()) {
			LOTLSigningCertificatesAnnouncementSchemeInformationURI signCertAnnouncementPredicate = lotlSource.getSigningCertificatesAnnouncementPredicate();
			String signCertAnnouncementURL = signCertAnnouncementPredicate != null ? signCertAnnouncementPredicate.getUri() : null;

			final List<String> filteredPivots = new ArrayList<>();
			for (NonEmptyMultiLangURIType nonEmptyMultiLangURIType : schemeInformationURI.getURI()) {
				if (new PivotSchemeInformationURI().test(nonEmptyMultiLangURIType)) {
					filteredPivots.add(nonEmptyMultiLangURIType.getValue());
				}
				// check if OJ URL is reached
				if (signCertAnnouncementURL != null && signCertAnnouncementURL.equals(nonEmptyMultiLangURIType.getValue())) {
					break;
				}
			}
			result.setPivotURLs(filteredPivots);
		}
	}

	@Override
	protected TrustedListFacade createTrustedListFacade() {
		if (lotlSource.isMraSupport()) {
			return MRAFacade.newFacade();
		} else {
			return super.createTrustedListFacade();
		}
	}

}
