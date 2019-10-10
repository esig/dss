package eu.europa.esig.dss.tsl.parsing;

import java.util.List;
import java.util.Objects;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.tsl.function.LOTLSigningCertificatesAnnouncementSchemeInformationURI;
import eu.europa.esig.dss.tsl.function.PivotSchemeInformationURI;
import eu.europa.esig.dss.tsl.function.converter.OtherTSLPointerConverter;
import eu.europa.esig.dss.tsl.source.LOTLSource;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.trustedlist.jaxb.tsl.NonEmptyMultiLangURIListType;
import eu.europa.esig.trustedlist.jaxb.tsl.OtherTSLPointerType;
import eu.europa.esig.trustedlist.jaxb.tsl.OtherTSLPointersType;
import eu.europa.esig.trustedlist.jaxb.tsl.TSLSchemeInformationType;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;

public class LOTLParsingTask extends AbstractParsingTask implements Supplier<LOTLParsingResult> {

	private static final Logger LOG = LoggerFactory.getLogger(LOTLParsingTask.class);

	private final LOTLSource lotlSource;

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

			OtherTSLPointerConverter converter = new OtherTSLPointerConverter();

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
			List<String> uris = schemeInformationURI.getURI().stream().filter(signingCertificatesAnnouncementPredicate).map(t -> t.getValue())
					.collect(Collectors.toList());
			if (Utils.isCollectionNotEmpty(uris)) {
				if (uris.size() > 1) {
					LOG.warn("More than 1 LOTLSigningCertificatesAnnouncement URI found (returns the first entry) : {}", uris);
				}
				result.setSigningCertificateAnnouncementURL(uris.get(0));
			}
		}
	}

	private void extractPivotURLs(LOTLParsingResult result, NonEmptyMultiLangURIListType schemeInformationURI) {
		if (lotlSource.isPivotSupport()) {
			List<String> uris = schemeInformationURI.getURI().stream().filter(new PivotSchemeInformationURI()).map(t -> t.getValue())
					.collect(Collectors.toList());
			result.setPivotURLs(uris);
		}
	}

}
