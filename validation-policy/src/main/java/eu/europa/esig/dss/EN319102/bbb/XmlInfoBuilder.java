package eu.europa.esig.dss.EN319102.bbb;

import java.util.ArrayList;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.List;

import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.jaxb.detailedreport.XmlInfo;

public class XmlInfoBuilder {
	
	private static final Logger logger = LoggerFactory.getLogger(XmlInfoBuilder.class);

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
		info.setRevokedDate(dateToXmlGregorianCalendare(revocationDate));
		info.setValue(reason);
		return info;
	}
	
	public static XmlInfo createNextUpadteInfo(Date nextUpdateDate) {
		XmlInfo info = new XmlInfo();
		info.setNextUpdateDate(dateToXmlGregorianCalendare(nextUpdateDate));
		return info;
	}
	
	public static XmlInfo createAlgoExpirationDateInfo(String algo, Date expirationDate) {
		XmlInfo info = new XmlInfo();
		info.setAlgoExpirationDate(dateToXmlGregorianCalendare(expirationDate));
		info.setValue(algo);
		return info;
	}
	
	private static XMLGregorianCalendar dateToXmlGregorianCalendare(Date date) {
		try {
			GregorianCalendar calendar = new GregorianCalendar();
			calendar.setTime(date);
			return DatatypeFactory.newInstance().newXMLGregorianCalendar(calendar);
		} catch(Exception e) {
			logger.info("The date to convert for the XmlInfo is null");
			return null;
		}
	}
}
