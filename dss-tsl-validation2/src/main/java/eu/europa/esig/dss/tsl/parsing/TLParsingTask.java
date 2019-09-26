package eu.europa.esig.dss.tsl.parsing;

import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.tsl.function.NonEmptyTrustService;
import eu.europa.esig.dss.tsl.function.converter.TrustServiceProviderConverter;
import eu.europa.esig.dss.tsl.source.TLSource;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.trustedlist.jaxb.tsl.TSLSchemeInformationType;
import eu.europa.esig.trustedlist.jaxb.tsl.TSPServiceType;
import eu.europa.esig.trustedlist.jaxb.tsl.TSPServicesListType;
import eu.europa.esig.trustedlist.jaxb.tsl.TSPType;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustServiceProviderListType;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;

public class TLParsingTask extends AbstractParsingTask implements Supplier<TLParsingResult> {

	private final TLSource tlSource;

	public TLParsingTask(DSSDocument document, TLSource tlSource) {
		super(document);
		Objects.requireNonNull(tlSource, "The TLSource is null");
		this.tlSource = tlSource;
	}

	@Override
	public TLParsingResult get() {

		TLParsingResult result = new TLParsingResult();

		TrustStatusListType jaxbObject = getJAXBObject();

		parseSchemeInformation(result, jaxbObject.getSchemeInformation());

		parseTrustServiceProviderList(result, jaxbObject.getTrustServiceProviderList());

		return result;
	}

	private void parseSchemeInformation(TLParsingResult result, TSLSchemeInformationType schemeInformation) {

		commonParseSchemeInformation(result, schemeInformation);

	}

	private void parseTrustServiceProviderList(TLParsingResult result, TrustServiceProviderListType trustServiceProviderList) {
		if (trustServiceProviderList != null && Utils.isCollectionNotEmpty(trustServiceProviderList.getTrustServiceProvider())) {
			List<TSPType> filteredTrustServiceProviders = filter(trustServiceProviderList.getTrustServiceProvider());
			result.setTrustServiceProviders(Collections.unmodifiableList(
					filteredTrustServiceProviders.stream().map(new TrustServiceProviderConverter()).collect(Collectors.toList())));
		} else {
			result.setTrustServiceProviders(Collections.emptyList());
		}
	}

	private List<TSPType> filter(List<TSPType> trustServiceProviders) {

		List<TSPType> filteredTSP = trustServiceProviders;

		// 1. Filter the TSP with the predicate
		if (tlSource.getTrustServiceProviderPredicate() != null) {
			filteredTSP = filteredTSP.stream().filter(tlSource.getTrustServiceProviderPredicate()).collect(Collectors.toList());
		}

		// 2. Foreach TSP, filter the trust services with the predicate
		if (tlSource.getTrustServicePredicate() != null) {
			for (TSPType tspType : filteredTSP) {
				TSPServicesListType tspServices = tspType.getTSPServices();
				if (tspServices != null && Utils.isCollectionNotEmpty(tspServices.getTSPService())) {
					List<TSPServiceType> filteredTrustServices = tspServices.getTSPService().stream().filter(tlSource.getTrustServicePredicate())
							.collect(Collectors.toList());
					TSPServicesListType newTspServices = new TSPServicesListType();
					if (!filteredTrustServices.isEmpty()) {
						newTspServices.getTSPService().addAll(filteredTrustServices);
					}
					tspType.setTSPServices(newTspServices);
				}
			}
		}

		// 3. Remove TSP with empty trust services
		return filteredTSP.stream().filter(new NonEmptyTrustService()).collect(Collectors.toList());
	}
}
