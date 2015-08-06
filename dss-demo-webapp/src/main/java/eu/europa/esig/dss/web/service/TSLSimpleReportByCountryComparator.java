package eu.europa.esig.dss.web.service;

import java.util.Comparator;

import eu.europa.esig.dss.tsl.TSLSimpleReport;

public class TSLSimpleReportByCountryComparator implements Comparator<TSLSimpleReport> {

	@Override
	public int compare(TSLSimpleReport o1, TSLSimpleReport o2) {
		return o1.getCountry().compareTo(o2.getCountry());
	}

}
