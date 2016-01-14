package eu.europa.esig.dss.EN319102.bbb;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import eu.europa.esig.dss.jaxb.detailedreport.XmlInfo;

public class XmlInfoBuilder {

	public static XmlInfo createCertificateIdInfo(String id) {
		XmlInfo info = new XmlInfo();
		info.setCertificateId(id);
		return info;
	}

	public static List<XmlInfo> createFieldsInfo(String indication, String subIndication) {
		List<XmlInfo> infos = new ArrayList<XmlInfo>();
		XmlInfo info = new XmlInfo();
		info.setField("Indication");
		info.setValue(indication);
		infos.add(info);

		info = new XmlInfo();
		info.setField("SubIndication");
		info.setValue(subIndication);
		infos.add(info);
		return infos;
	}

	public static XmlInfo createRevocationInfo(Date revocationDate, String reason) {
		XmlInfo info = new XmlInfo();
		info.setRevokedDate(revocationDate);
		info.setValue(reason);
		return info;
	}

	public static XmlInfo createNextUpadteInfo(Date nextUpdateDate) {
		XmlInfo info = new XmlInfo();
		info.setNextUpdateDate(nextUpdateDate);
		return info;
	}

	public static XmlInfo createAlgoExpirationDateInfo(String algo, Date expirationDate) {
		XmlInfo info = new XmlInfo();
		info.setAlgoExpirationDate(expirationDate);
		info.setValue(algo);
		return info;
	}

}
