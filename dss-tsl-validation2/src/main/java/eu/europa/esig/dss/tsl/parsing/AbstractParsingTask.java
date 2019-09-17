package eu.europa.esig.dss.tsl.parsing;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.util.Date;
import java.util.GregorianCalendar;

import javax.xml.datatype.XMLGregorianCalendar;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.tsl.download.XmlDownloadResult;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.trustedlist.TrustedListFacade;
import eu.europa.esig.trustedlist.jaxb.tsl.NextUpdateType;
import eu.europa.esig.trustedlist.jaxb.tsl.NonEmptyURIListType;
import eu.europa.esig.trustedlist.jaxb.tsl.TSLSchemeInformationType;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;

public abstract class AbstractParsingTask {

	private final XmlDownloadResult downloadResult;

	protected AbstractParsingTask(XmlDownloadResult downloadResult) {
		this.downloadResult = downloadResult;
	}

	protected TrustStatusListType getJAXBObject() {
		try (ByteArrayInputStream bais = new ByteArrayInputStream(downloadResult.getContent())) {
			return TrustedListFacade.newFacade().unmarshall(bais);
		} catch (Exception e) {
			throw new DSSException("Unable to parse binaries", e);
		}
	}

	protected void commonParseSchemeInformation(CommonParsingResult result, TSLSchemeInformationType schemeInformation) {

		extractSequenceNumber(result, schemeInformation);
		extractTerritory(result, schemeInformation);
		extractVersion(result, schemeInformation);
		extractIssueDate(result, schemeInformation);
		extractNextUpdateDate(result, schemeInformation);
		extractDistributionPoints(result, schemeInformation);

	}

	private void extractSequenceNumber(CommonParsingResult result, TSLSchemeInformationType schemeInformation) {
		BigInteger tslSequenceNumber = schemeInformation.getTSLSequenceNumber();
		if (tslSequenceNumber != null) {
			result.setSequenceNumber(tslSequenceNumber.intValue());
		}
	}

	private void extractTerritory(CommonParsingResult result, TSLSchemeInformationType schemeInformation) {
		result.setTerritory(schemeInformation.getSchemeTerritory());
	}

	private void extractVersion(CommonParsingResult result, TSLSchemeInformationType schemeInformation) {
		BigInteger tslVersionIdentifier = schemeInformation.getTSLVersionIdentifier();
		if (tslVersionIdentifier != null) {
			result.setVersion(tslVersionIdentifier.intValue());
		}
	}

	private void extractIssueDate(CommonParsingResult result, TSLSchemeInformationType schemeInformation) {
		result.setIssueDate(convertToDate(schemeInformation.getListIssueDateTime()));
	}

	private void extractNextUpdateDate(CommonParsingResult result, TSLSchemeInformationType schemeInformation) {
		NextUpdateType nextUpdate = schemeInformation.getNextUpdate();
		if (nextUpdate != null) {
			result.setNextUpdateDate(convertToDate(nextUpdate.getDateTime()));
		}
	}

	private Date convertToDate(XMLGregorianCalendar gregorianCalendar) {
		if (gregorianCalendar != null) {
			GregorianCalendar toGregorianCalendar = gregorianCalendar.toGregorianCalendar();
			if (toGregorianCalendar != null) {
				return toGregorianCalendar.getTime();
			}
		}
		return null;
	}

	private void extractDistributionPoints(CommonParsingResult result, TSLSchemeInformationType schemeInformation) {
		NonEmptyURIListType distributionPoints = schemeInformation.getDistributionPoints();
		if (distributionPoints != null && Utils.isCollectionNotEmpty(distributionPoints.getURI())) {
			result.setDistributionPoints(distributionPoints.getURI());
		}
	}

}
